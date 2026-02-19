from pathlib import Path
from queue import Empty, Queue
from unittest.mock import patch

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.preprocessing import MinMaxScaler

from ddos_martummai.preprocessor import (
    DDoSPreprocessor,
    clean_column_names,
    convert_to_float32,
    handle_infinite_values,
    handle_missing_values,
    load_scaler,
    process_batch,
    rename_columns,
    save_scaler,
    scale_features,
    select_numeric_columns,
)
from ddos_martummai.util.constant import COLUMN_RENAME_MAP


@pytest.fixture
def dummy_scaler_path(tmp_path):
    scaler_file = tmp_path / "dummy_scaler.joblib"

    dummy_data = pd.DataFrame(
        {
            "f1": [0, 100],  # Min 0, Max 100
            "f2": [0, 10],  # Min 0, Max 10
        }
    )

    scaler = MinMaxScaler()
    scaler.fit(dummy_data)
    joblib.dump(scaler, scaler_file)

    return str(scaler_file)


@pytest.fixture
def real_scaler_path():
    root_dir = Path(__file__).parent.parent
    scaler_file = root_dir / "src" / "ddos_martummai" / "models" / "scaler.joblib"

    if not scaler_file.exists():
        pytest.fail(f"Real scaler.joblib not found at {scaler_file}")

    return str(scaler_file)


@pytest.fixture
def sample_raw_df():
    return pd.DataFrame(
        {
            "src_ip": ["192.168.1.1", "10.0.0.1", "1.1.1.1"],
            " feature_1 ": [50, np.nan, 100],  # have whitespace and NaN
            "feature_2": [5, np.inf, -np.inf],  # have Infinity
        }
    )


def test_clean_column_names():
    df = pd.DataFrame(columns=[" src_ip ", "feature_1  ", "  feature_2"])
    cleaned_df = clean_column_names(df)
    assert list(cleaned_df.columns) == ["src_ip", "feature_1", "feature_2"]


def test_select_numeric_columns():
    df = pd.DataFrame({"src_ip": ["1.1.1.1"], "feature_1": [10], "feature_2": [20]})
    src_ip_df, feature_df = select_numeric_columns(df, ["feature_1", "feature_2"])

    assert list(src_ip_df.columns) == ["src_ip"]
    assert list(feature_df.columns) == ["feature_1", "feature_2"]


def test_handle_missing_values():
    df = pd.DataFrame(
        {
            "col1": [10, np.nan, 30],  # Median = 20
            "col2": [1, 2, 3],
        }
    )
    result = handle_missing_values(df)
    assert result.isnull().sum().sum() == 0
    assert result["col1"].iloc[1] == 20.0


def test_handle_infinite_values():
    df = pd.DataFrame(
        {
            "col1": [10, np.inf, 30, -np.inf]  # Median = 20
        }
    )
    result = handle_infinite_values(df)
    assert not np.isinf(result.values).any()
    assert result["col1"].iloc[1] == 20.0
    assert result["col1"].iloc[3] == 20.0


def test_rename_columns():
    df = pd.DataFrame({"old_1": [1], "old_2": [2]})
    rename_map = {"old_1": "new_1", "old_2": "new_2"}
    result = rename_columns(df, rename_map)
    assert list(result.columns) == ["new_1", "new_2"]


def test_convert_to_float32():
    df = pd.DataFrame({"col1": [1, 2], "col2": [3.5, 4.5]})
    result = convert_to_float32(df)
    assert result["col1"].dtype == np.float32
    assert result["col2"].dtype == np.float32


def test_scale_features(dummy_scaler_path):
    scaler = load_scaler(dummy_scaler_path)
    df = pd.DataFrame({"f1": [50], "f2": [5]})

    result = scale_features(df, scaler)

    assert pytest.approx(result["f1"].iloc[0]) == 0.5
    assert pytest.approx(result["f2"].iloc[0]) == 0.5


def test_load_scaler_not_found():
    with pytest.raises(FileNotFoundError):
        load_scaler("invalid/path/scaler.joblib")


@patch(
    "ddos_martummai.preprocessor.COLUMN_RENAME_MAP",
    {"feature_1": "f1", "feature_2": "f2"},
)
def test_process_batch_success(sample_raw_df, dummy_scaler_path):
    scaler = load_scaler(dummy_scaler_path)

    result_df = process_batch(sample_raw_df, scaler, batch_size=3)

    assert len(result_df) == 3
    assert list(result_df.columns) == ["src_ip", "f1", "f2"]
    assert not result_df.isnull().values.any()
    assert not np.isinf(result_df.iloc[:, 1:].values).any()

    assert pytest.approx(result_df["f1"].iloc[0]) == 0.5


@patch(
    "ddos_martummai.preprocessor.COLUMN_RENAME_MAP",
    {"feature_1": "f1", "feature_2": "f2"},
)
def test_process_batch_chunks_data_correctly(dummy_scaler_path):
    scaler = load_scaler(dummy_scaler_path)

    df_large = pd.DataFrame(
        {
            "src_ip": ["IP1", "IP2", "IP3", "IP4", "IP5"],
            "feature_1": [10, 20, 30, 40, 50],
            "feature_2": [1, 2, 3, 4, 5],
        }
    )

    # Use a batch size of 2 to force multiple batches
    # This will test that the function correctly processes multiple batches and concatenates results
    result_df = process_batch(df_large, scaler, batch_size=2)

    assert len(result_df) == 5
    assert list(result_df["src_ip"]) == ["IP1", "IP2", "IP3", "IP4", "IP5"]
    assert list(result_df.columns) == ["src_ip", "f1", "f2"]


@patch(
    "ddos_martummai.preprocessor.COLUMN_RENAME_MAP",
    {"feature_1": "f1", "feature_2": "f2"},
)
def test_process_batch_when_input_data_is_empty(dummy_scaler_path):
    scaler = load_scaler(dummy_scaler_path)
    empty_df = pd.DataFrame(columns=["src_ip", "feature_1", "feature_2"])

    result_df = process_batch(empty_df, scaler, batch_size=2)

    assert result_df.empty


@patch(
    "ddos_martummai.preprocessor.COLUMN_RENAME_MAP",
    {"feature_1": "f1", "feature_2": "f2"},
)
def test_start_flushes_on_batch_size(dummy_scaler_path):
    raw_q = Queue()
    preprocessor = DDoSPreprocessor(
        dummy_scaler_path, batch_size=2, raw_packet_queue=raw_q
    )

    raw_q.put({"src_ip": "1.1.1.1", "feature_1": 10, "feature_2": 5})
    raw_q.put({"src_ip": "2.2.2.2", "feature_1": 20, "feature_2": 6})
    raw_q.put(None)

    preprocessor.start()

    out_q = preprocessor.get_queue()
    assert out_q.qsize() == 2

    df_result = out_q.get()
    assert isinstance(df_result, pd.DataFrame)
    assert len(df_result) == 2
    assert out_q.get() is None


@patch(
    "ddos_martummai.preprocessor.COLUMN_RENAME_MAP",
    {"feature_1": "f1", "feature_2": "f2"},
)
def test_start_flushes_on_timeout(dummy_scaler_path):
    raw_q = Queue()
    preprocessor = DDoSPreprocessor(
        dummy_scaler_path, batch_size=10, raw_packet_queue=raw_q
    )

    raw_q.put({"src_ip": "1.1.1.1", "feature_1": 10, "feature_2": 5})

    from queue import Empty

    original_get = raw_q.get

    def mock_get(*args, **kwargs):
        if raw_q.empty():
            if not hasattr(mock_get, "empty_raised"):
                mock_get.empty_raised = True
                raise Empty()
            return None
        return original_get(*args, **kwargs)

    with patch.object(raw_q, "get", side_effect=mock_get):
        preprocessor.start()

    out_q = preprocessor.get_queue()
    assert out_q.qsize() == 2
    assert len(out_q.get()) == 1


def test_process_batch_exception(sample_raw_df, dummy_scaler_path):
    """ทดสอบกรณี process_batch พังกลางคัน (Lines 130-135)"""
    scaler = load_scaler(dummy_scaler_path)

    # จำลองให้ฟังก์ชันข้างในตัวนึงพัง เพื่อให้หลุดเข้า except block
    with patch(
        "ddos_martummai.preprocessor.clean_column_names",
        side_effect=Exception("Simulated Error"),
    ):
        with pytest.raises(Exception, match="Simulated Error"):
            process_batch(sample_raw_df, scaler, batch_size=2)


def test_standalone_save_scaler(tmp_path):
    """ทดสอบการบันทึก Scaler แบบเดี่ยวๆ (Lines 143-147)"""
    scaler = MinMaxScaler()
    out_path = tmp_path / "test_standalone_scaler.joblib"

    save_scaler(scaler, str(out_path))

    assert out_path.exists()


def test_class_save_scaler_success(dummy_scaler_path, tmp_path):
    preprocessor = DDoSPreprocessor(
        dummy_scaler_path, batch_size=10, raw_packet_queue=Queue()
    )
    out_path = tmp_path / "class_scaler.joblib"

    preprocessor.save_scaler(str(out_path))

    assert out_path.exists()


def test_class_save_scaler_raises_value_error(dummy_scaler_path):
    preprocessor = DDoSPreprocessor(
        dummy_scaler_path, batch_size=10, raw_packet_queue=Queue()
    )
    preprocessor.scaler = None

    with pytest.raises(ValueError, match="No scaler to save"):
        preprocessor.save_scaler("some_path.joblib")


def test_flush_buffer_exception(dummy_scaler_path):
    preprocessor = DDoSPreprocessor(
        dummy_scaler_path, batch_size=2, raw_packet_queue=Queue()
    )

    # Simulate an exception in the transform step to trigger the except block
    with patch.object(
        preprocessor, "transform", side_effect=Exception("Transform Error")
    ):
        result = preprocessor.flush_buffer([{"src_ip": "1.1.1.1", "f1": 1}])

        assert result is False


def test_start_flush_failure_on_none(dummy_scaler_path):
    q = Queue()
    q.put({"src_ip": "1.1.1.1", "f1": 1})
    q.put(None)

    preprocessor = DDoSPreprocessor(
        dummy_scaler_path, batch_size=10, raw_packet_queue=q
    )

    with patch.object(preprocessor, "flush_buffer", return_value=False):
        preprocessor.start()

    assert preprocessor.get_queue().empty()


def test_start_flush_failure_on_batch_size(dummy_scaler_path):
    q = Queue()
    q.put({"src_ip": "1.1.1.1", "f1": 1})
    q.put({"src_ip": "1.1.1.2", "f1": 2})

    preprocessor = DDoSPreprocessor(dummy_scaler_path, batch_size=2, raw_packet_queue=q)

    with patch.object(preprocessor, "flush_buffer", return_value=False):
        preprocessor.start()

    out_q = preprocessor.get_queue()
    assert out_q.qsize() == 1
    assert out_q.get() is None


def test_start_flush_failure_on_timeout(dummy_scaler_path):
    q = Queue()
    q.put({"src_ip": "1.1.1.1", "f1": 1})

    original_get = q.get

    def mock_get(*args, **kwargs):
        if q.empty():
            raise Empty()
        return original_get(*args, **kwargs)

    preprocessor = DDoSPreprocessor(
        dummy_scaler_path, batch_size=10, raw_packet_queue=q
    )

    with patch.object(q, "get", side_effect=mock_get):
        with patch.object(preprocessor, "flush_buffer", return_value=False):
            preprocessor.start()

    out_q = preprocessor.get_queue()
    assert out_q.qsize() == 1
    assert out_q.get() is None


# INTEGRATION TEST


def test_integration_full_pipeline_with_real_scaler(real_scaler_path):
    test_csv_path = Path(__file__).parent / "fixtures" / "sample_raw.csv"

    if not test_csv_path.exists():
        pytest.fail(
            f"{test_csv_path} not found. Please ensure the fixture file is in place."
        )

    incoming_data = pd.read_csv(test_csv_path)

    raw_q = Queue()
    for record in incoming_data.to_dict("records"):
        raw_q.put(record)
    raw_q.put(None)

    preprocessor = DDoSPreprocessor(
        real_scaler_path, batch_size=10, raw_packet_queue=raw_q
    )
    preprocessor.start()

    out_q = preprocessor.get_queue()
    final_df = out_q.get()

    assert final_df is not None
    assert len(final_df) == len(incoming_data)

    expected_features = list(COLUMN_RENAME_MAP.values())
    expected_columns = ["src_ip"] + expected_features

    assert list(final_df.columns) == expected_columns, (
        "column names after preprocessing do not match expected (check rename_columns and COLUMN_RENAME_MAP)"
    )

    numeric_df = final_df.iloc[:, 1:]
    assert not numeric_df.empty, "not have numeric features after preprocessing"

    assert numeric_df.dtypes.apply(lambda x: x == np.float32).all(), (
        "numeric features not converted to float32 as expected (check convert_to_float32 function)"
    )

    assert not numeric_df.isnull().values.any(), "have NaN values in final output"
    assert not np.isinf(numeric_df.values).any(), "have Inf values in final output"
