from queue import Queue
from unittest.mock import patch

import numpy as np
import pandas as pd

from ddos_martummai.preprocessor import (
    DDoSPreprocessor,
    clean_column_names,
    handle_infinite_values,
    handle_missing_values,
)


def test_clean_column_names_dirty_cols_returns_stripped(sample_dataframe):
    df = clean_column_names(sample_dataframe)
    assert "Flow Duration" in df.columns
    assert " Flow Duration" not in df.columns


def test_handle_missing_values_nan_present_fills_median():
    df = pd.DataFrame({"A": [1, np.nan, 3]})
    processed = handle_missing_values(df)
    assert processed["A"].isnull().sum() == 0
    assert processed["A"][1] == 2.0


def test_handle_infinite_values_inf_present_fills_median():
    df = pd.DataFrame({"A": [1, np.inf, 3]})
    processed = handle_infinite_values(df)
    assert not np.isinf(processed["A"]).any()
    assert processed["A"][1] == 2.0


def test_preprocessor_start_valid_queue_processes_batch(mock_scaler):
    input_q = Queue()
    packet = {
        "src_ip": "1.1.1.1",
        "col_0": 10,
        "col_1": 20,
        "col_2": 30,
        "col_3": 40,
        "col_4": 50,
    }
    input_q.put(packet)
    input_q.put(None)

    with patch("ddos_martummai.preprocessor.load_scaler", return_value=mock_scaler):
        processor = DDoSPreprocessor(
            "dummy_path", batch_size=1, raw_packet_queue=input_q
        )
        processor.start()

        result = processor.get_queue().get()
        assert isinstance(result, pd.DataFrame)
        assert len(result) == 1


def test_preprocessor_start_empty_buffer_stops_gracefully(mock_scaler):
    input_q = Queue()
    input_q.put(None)

    with patch("ddos_martummai.preprocessor.load_scaler", return_value=mock_scaler):
        processor = DDoSPreprocessor(
            "dummy_path", batch_size=1, raw_packet_queue=input_q
        )
        processor.start()

        result = processor.get_queue().get()
        assert result is None
