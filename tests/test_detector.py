from queue import Queue
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

from ddos_martummai.detector import DDoSDetector


@pytest.fixture
def mock_ml_model():
    model = MagicMock()
    model.predict.return_value = [0, 1]
    return model


def test_load_model_file_missing_exits(mock_app_config, tmp_path):
    q = Queue()
    with patch("sys.exit") as mock_exit:
        DDoSDetector(tmp_path / "missing.joblib", mock_app_config, q)
        mock_exit.assert_called_with(1)


def test_predict_batch_valid_dataframe_logs_output(
    mock_app_config, mock_ml_model, tmp_path
):
    q = Queue()
    model_path = tmp_path / "model.joblib"
    model_path.touch()

    with patch("joblib.load", return_value=mock_ml_model):
        detector = DDoSDetector(model_path, mock_app_config, q)

        df = pd.DataFrame({"src_ip": ["1.1.1.1", "2.2.2.2"], "feat1": [1, 2]})

        with patch("ddos_martummai.detector.logger.info") as mock_log:
            detector._predict_batch(df)
            mock_ml_model.predict.assert_called()
            mock_log.assert_called()


def test_start_none_in_queue_stops_loop(mock_app_config, mock_ml_model, tmp_path):
    q = Queue()
    q.put(None)
    model_path = tmp_path / "model.joblib"
    model_path.touch()

    with patch("joblib.load", return_value=mock_ml_model):
        detector = DDoSDetector(model_path, mock_app_config, q)
        detector.start()  # Should return immediately
