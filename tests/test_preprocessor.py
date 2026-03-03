from multiprocessing import Queue
from pathlib import Path
from queue import Empty
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
    """Creates a dummy MinMaxScaler for testing transformation logic."""
    scaler_file = tmp_path / "dummy_scaler.joblib"
    dummy_data = pd.DataFrame({"f1": [0, 100], "f2": [0, 10]})
    scaler = MinMaxScaler()
    scaler.fit(dummy_data)
    joblib.dump(scaler, scaler_file)
    return str(scaler_file)


@pytest.fixture
def real_scaler_path():
    """Points to the actual scaler file used in production."""
    root_dir = Path(__file__).parent.parent
    scaler_file = root_dir / "src" / "ddos_martummai" / "ml" / "scaler.joblib"
    if not scaler_file.exists():
        pytest.fail(f"Real scaler.joblib not found at {scaler_file}")
    return str(scaler_file)


@pytest.fixture
def sample_raw_df():
    """Provides a dataframe with dirty data (spaces, NaN, Inf) to test cleaning."""
    return pd.DataFrame(
        {
            "src_ip": ["192.168.1.1", "10.0.0.1", "1.1.1.1"],
            " feature_1 ": [50, np.nan, 100],
            "feature_2": [5, np.inf, -np.inf],
        }
    )


@pytest.fixture
def raw_q():
    """Provides a multiprocessing Queue for raw packets."""
    return Queue()


@pytest.fixture
def clean_q():
    """Provides a multiprocessing Queue for cleaned, processed DataFrames."""
    return Queue()


@pytest.fixture
def preprocessor(dummy_scaler_path, raw_q, clean_q):
    """Creates a ready-to-use preprocessor instance with dummy scaler and queues."""
    return DDoSPreprocessor(
        scaler_path=dummy_scaler_path,
        batch_size=2,
        raw_packet_queue=raw_q,
        cleaned_packet_queue=clean_q,
    )


# TESTS: PURE FUNCTIONS


def test_clean_column_names():
    # Tests if leading/trailing whitespaces are removed from column names
    df = pd.DataFrame(columns=[" src_ip ", "feature_1  ", "  feature_2"])
    cleaned_df = clean_column_names(df)
    assert list(cleaned_df.columns) == ["src_ip", "feature_1", "feature_2"]


def test_select_numeric_columns():
    # Tests if src_ip is correctly separated from feature columns
    df = pd.DataFrame({"src_ip": ["1.1.1.1"], "feature_1": [10], "feature_2": [20]})
    src_ip_df, feature_df = select_numeric_columns(df, ["feature_1", "feature_2"])
    assert list(src_ip_df.columns) == ["src_ip"]
    assert list(feature_df.columns) == ["feature_1", "feature_2"]


def test_handle_missing_values():
    # Tests if NaN values are replaced with the column's median
    df = pd.DataFrame(
        {"col1": [10, np.nan, 30], "col2": [1, 2, 3]}
    )  # Median for col1 is 20
    result = handle_missing_values(df)
    assert result.isnull().sum().sum() == 0
    assert result["col1"].iloc[1] == 20.0


def test_handle_infinite_values():
    # Tests if Infinity values are replaced with median
    df = pd.DataFrame({"col1": [10, np.inf, 30, -np.inf]})  # Median ignoring inf is 20
    result = handle_infinite_values(df)
    assert not np.isinf(result.values).any()
    assert result["col1"].iloc[1] == 20.0
    assert result["col1"].iloc[3] == 20.0


def test_rename_columns():
    # Tests if columns are successfully renamed using the provided dictionary
    df = pd.DataFrame({"old_1": [1], "old_2": [2]})
    rename_map = {"old_1": "new_1", "old_2": "new_2"}
    result = rename_columns(df, rename_map)
    assert list(result.columns) == ["new_1", "new_2"]


def test_convert_to_float32():
    # Tests memory optimization conversion to float32
    df = pd.DataFrame({"col1": [1, 2], "col2": [3.5, 4.5]})
    result = convert_to_float32(df)
    assert result["col1"].dtype == np.float32
    assert result["col2"].dtype == np.float32


def test_scale_features(dummy_scaler_path):
    # Tests if the dataframe values are normalized properly (0.0 to 1.0)
    scaler = load_scaler(dummy_scaler_path)
    df = pd.DataFrame({"f1": [50], "f2": [5]})
    result = scale_features(df, scaler)
    assert pytest.approx(result["f1"].iloc[0]) == 0.5
    assert pytest.approx(result["f2"].iloc[0]) == 0.5


def test_load_scaler_not_found():
    # Expect a FileNotFoundError when path is invalid
    with pytest.raises(FileNotFoundError):
        load_scaler("invalid/path/scaler.joblib")


# TESTS: PIPELINE BATCH PROCESSING


def test_process_batch_success(sample_raw_df, dummy_scaler_path):
    # Tests the full pure function pipeline: Clean -> Fill NaN -> Scale -> Combine
    scaler = load_scaler(dummy_scaler_path)

    with patch(
        "ddos_martummai.preprocessor.COLUMN_RENAME_MAP",
        {"feature_1": "f1", "feature_2": "f2"},
    ):
        result_df = process_batch(sample_raw_df, scaler, batch_size=3)

    assert len(result_df) == 3
    assert list(result_df.columns) == ["src_ip", "f1", "f2"]
    assert not result_df.isnull().values.any()
    assert not np.isinf(result_df.iloc[:, 1:].values).any()
    assert pytest.approx(result_df["f1"].iloc[0]) == 0.5


def test_process_batch_chunks_data_correctly(dummy_scaler_path):
    # Tests if batch_size splits and concatenates data accurately
    scaler = load_scaler(dummy_scaler_path)
    df_large = pd.DataFrame(
        {
            "src_ip": ["IP1", "IP2", "IP3", "IP4", "IP5"],
            "feature_1": [10, 20, 30, 40, 50],
            "feature_2": [1, 2, 3, 4, 5],
        }
    )

    with patch(
        "ddos_martummai.preprocessor.COLUMN_RENAME_MAP",
        {"feature_1": "f1", "feature_2": "f2"},
    ):
        result_df = process_batch(df_large, scaler, batch_size=2)

    assert len(result_df) == 5
    assert list(result_df["src_ip"]) == ["IP1", "IP2", "IP3", "IP4", "IP5"]


def test_process_batch_when_input_data_is_empty(dummy_scaler_path):
    # Tests behavior when an empty dataframe is passed
    scaler = load_scaler(dummy_scaler_path)
    empty_df = pd.DataFrame(columns=["src_ip", "feature_1", "feature_2"])

    with patch(
        "ddos_martummai.preprocessor.COLUMN_RENAME_MAP",
        {"feature_1": "f1", "feature_2": "f2"},
    ):
        result_df = process_batch(empty_df, scaler, batch_size=2)

    assert result_df.empty


def test_process_batch_exception(sample_raw_df, dummy_scaler_path):
    # Simulates an unexpected error to ensure it propagates correctly
    scaler = load_scaler(dummy_scaler_path)
    with patch(
        "ddos_martummai.preprocessor.clean_column_names",
        side_effect=Exception("Simulated Error"),
    ):
        with pytest.raises(Exception, match="Simulated Error"):
            process_batch(sample_raw_df, scaler, batch_size=2)


# TESTS: DDOS PREPROCESSOR CLASS


def test_start_flushes_on_batch_size(preprocessor, raw_q, clean_q):
    # Tests if the class flushes exactly when the buffer reaches batch_size (2)
    raw_q.put({"src_ip": "1.1.1.1", "feature_1": 10, "feature_2": 5})
    raw_q.put({"src_ip": "2.2.2.2", "feature_1": 20, "feature_2": 6})
    raw_q.put(None)  # Sentinel to break the infinite loop cleanly

    with patch(
        "ddos_martummai.preprocessor.COLUMN_RENAME_MAP",
        {"feature_1": "f1", "feature_2": "f2"},
    ):
        preprocessor.start()

    # Get processed chunk
    df_result = clean_q.get(timeout=1)
    assert isinstance(df_result, pd.DataFrame)
    assert len(df_result) == 2

    # Get stop signal
    assert clean_q.get(timeout=1) is None


def test_start_flush_failure_on_timeout(preprocessor, raw_q, clean_q, caplog):
    # Tests if an unrecoverable flush error during timeout is caught and logged.
    raw_q.put({"src_ip": "1.1.1.1", "f1": 1})

    original_get = raw_q.get

    def mock_get(*args, **kwargs):
        if raw_q.empty():
            raise Empty()
        return original_get(*args, **kwargs)

    with patch.object(raw_q, "get", side_effect=mock_get):
        with patch.object(preprocessor, "flush_buffer", return_value=False):
            preprocessor.start()

    # Verify that the timeout-specific error message was logged
    assert "Unrecoverable error during timeout flush." in caplog.text

    # Verify graceful shutdown
    assert clean_q.get(timeout=1) is None


def test_start_flush_failure_on_batch_size(preprocessor, raw_q, clean_q, caplog):
    # Tests if an unrecoverable flush error is properly caught and logged,
    # and that the preprocessor shuts down gracefully without crashing.
    raw_q.put({"src_ip": "1.1.1.1", "f1": 1})
    raw_q.put({"src_ip": "1.1.1.2", "f1": 2})

    with patch.object(preprocessor, "flush_buffer", return_value=False):
        # Execute start. It will internally raise RuntimeError, catch it, log it, and stop.
        preprocessor.start()

    # 1. Verify that the correct error message was written to the logs
    assert "Unrecoverable error during batch flush." in caplog.text

    # 2. Verify that the finally block executed and sent the shutdown signal (None)
    assert clean_q.get(timeout=1) is None


def test_standalone_save_scaler(tmp_path):
    # Tests saving logic for standalone pure function
    scaler = MinMaxScaler()
    out_path = tmp_path / "test_standalone_scaler.joblib"
    save_scaler(scaler, str(out_path))
    assert out_path.exists()


def test_class_save_scaler_success(preprocessor, tmp_path):
    # Tests saving logic from within the class
    out_path = tmp_path / "class_scaler.joblib"
    preprocessor.save_scaler(str(out_path))
    assert out_path.exists()


def test_class_save_scaler_raises_value_error(preprocessor):
    # Tests error handling when attempting to save a non-existent scaler
    preprocessor.scaler = None
    with pytest.raises(ValueError, match="No scaler to save"):
        preprocessor.save_scaler("some_path.joblib")


def test_flush_buffer_exception(preprocessor):
    # Tests if transform exception is caught and returns False
    with patch.object(
        preprocessor, "transform", side_effect=Exception("Transform Error")
    ):
        result = preprocessor.flush_buffer([{"src_ip": "1.1.1.1", "f1": 1}])
        assert result is False


# INTEGRATION TEST


def test_integration_full_pipeline_with_real_scaler(real_scaler_path, raw_q, clean_q):
    # End-to-End Test: Feeds real CSV data and expects fully formatted model-ready data
    test_csv_path = Path(__file__).parent / "fixtures" / "sample_raw.csv"
    if not test_csv_path.exists():
        pytest.fail(f"{test_csv_path} not found.")

    incoming_data = pd.read_csv(test_csv_path)

    # Populate raw queue
    for record in incoming_data.to_dict("records"):
        raw_q.put(record)
    raw_q.put(None)  # Stop signal

    # Initialize with real scaler
    preprocessor = DDoSPreprocessor(
        scaler_path=real_scaler_path,
        batch_size=10,
        raw_packet_queue=raw_q,
        cleaned_packet_queue=clean_q,
    )
    preprocessor.start()

    # Retrieve output
    final_df = clean_q.get(timeout=2)

    assert final_df is not None
    assert len(final_df) == len(incoming_data)

    expected_features = list(COLUMN_RENAME_MAP.values())
    expected_columns = ["src_ip"] + expected_features

    assert list(final_df.columns) == expected_columns, "Column names mismatch"

    numeric_df = final_df.iloc[:, 1:]
    assert not numeric_df.empty, "Missing numeric features"
    assert numeric_df.dtypes.apply(lambda x: x == np.float32).all(), (
        "Data types must be float32"
    )
    assert not numeric_df.isnull().values.any(), "Pipeline failed to clear NaNs"
    assert not np.isinf(numeric_df.values).any(), "Pipeline failed to clear Infinity"
