from unittest.mock import MagicMock, patch

from ddos_martummai.reader import Reader


def test_reader_start_live_mode_runs_subprocess(mock_app_config):
    reader = Reader(mock_app_config, mode="live")
    with (
        patch("subprocess.Popen") as mock_popen,
        patch.object(reader, "_read_csv_live"),
    ):
        reader.start()
        mock_popen.assert_called()
        assert reader.running is True


def test_reader_read_csv_direct_valid_file_fills_queue(mock_app_config, tmp_path):
    reader = Reader(mock_app_config, mode="csv")
    csv_file = tmp_path / "test.csv"
    csv_file.write_text("col1,col2\n1,2")

    reader._read_csv_direct(csv_file)
    result = reader.get_queue().get()
    assert result["col1"] == 1


def test_reader_stop_terminates_process(mock_app_config):
    reader = Reader(mock_app_config)
    mock_process = MagicMock()
    reader.cic_process = mock_process

    reader.stop()
    mock_process.terminate.assert_called()
