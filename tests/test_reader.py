import subprocess
from pathlib import Path
from queue import Queue
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

from ddos_martummai.init_models import AppConfig, SystemConfig
from ddos_martummai.reader import Reader


@pytest.fixture
def mock_app_config(tmp_path):
    return AppConfig(
        system=SystemConfig(
            interface="eth0",
            csv_output_path=str(tmp_path / "data"),
            test_mode_output_path=str(tmp_path / "test_result.csv"),
            csv_rotation_rows=1000,
            google_drive_upload=False,
            token_file_path=str(tmp_path / "token.json"),
            google_drive_folder_id="folder123",
        )
    )


def test_init_when_valid_config(mock_app_config):
    reader = Reader(mock_app_config, mode="live")
    assert reader.config == mock_app_config
    assert reader.mode == "live"
    assert reader.running is False
    assert isinstance(reader.raw_packet_queue, Queue)


def test_get_queue_returns_correct_queue(mock_app_config):
    reader = Reader(mock_app_config)
    queue = reader.get_queue()
    assert queue is reader.raw_packet_queue


def test_start_when_mode_is_live_calls_run_live(mock_app_config):
    reader = Reader(mock_app_config, mode="live")

    with patch.object(reader, "_run_live") as mock_run_live:
        reader.start()

        mock_run_live.assert_called_once()
        # Verify shutdown signal (None) is put into queue
        assert reader.raw_packet_queue.get() is None


def test_start_when_unknown_mode_raises_error(mock_app_config):
    reader = Reader(mock_app_config, mode="AraiWah")

    with pytest.raises(ValueError, match="Unknown mode: AraiWah"):
        reader.start()

    # Verify shutdown signal is sent even on error
    assert reader.raw_packet_queue.get() is None


def test_run_live_flow_execution(mock_app_config):
    reader = Reader(mock_app_config, mode="live")

    with (
        patch.object(reader, "_prepare_csv_output") as mock_prep_csv,
        patch.object(reader, "_prepare_uploader") as mock_prep_uploader,
        patch.object(reader, "_start_cicflowmeter_live") as mock_start_cic,
        patch.object(reader, "_stream_csv") as mock_stream,
    ):
        reader._run_live()

        mock_prep_csv.assert_called_once()
        mock_prep_uploader.assert_called_once()
        mock_start_cic.assert_called_once()
        mock_stream.assert_called_once()


def test_prepare_csv_output_creates_directories_and_cleans_old_files(
    mock_app_config, tmp_path
):
    reader = Reader(mock_app_config)
    data_path = tmp_path / "output"

    # Setup directories and mock files
    data_path.mkdir(parents=True, exist_ok=True)
    cic_dir = data_path / "cic"
    cic_dir.mkdir(exist_ok=True)

    # Files to test deletion logic
    file_to_delete = cic_dir / "20261212_195012_flow_data_0.csv"
    file_to_keep = cic_dir / "20261212_195012_flow_data_prem.csv"
    file_to_delete.touch()
    file_to_keep.touch()

    reader._prepare_csv_output(data_path)

    assert reader.cic_output_dir == cic_dir
    assert reader.upload_queue_dir == data_path / "upload_queue"
    assert cic_dir.exists()
    assert reader.upload_queue_dir.exists()

    # Assertions for file cleaning
    assert not file_to_delete.exists()
    assert file_to_keep.exists()


def test_start_cicflowmeter_live_builds_correct_command(mock_app_config):
    reader = Reader(mock_app_config)
    reader.cic_output_dir = Path("/tmp/cic_out")

    with (
        patch("subprocess.Popen") as mock_popen,
        patch("os.path.dirname", return_value="/usr/bin"),
        patch("sys.executable", "/usr/bin/python"),
    ):
        reader._start_cicflowmeter_live()

        mock_popen.assert_called_once()
        cmd = mock_popen.call_args[0][0]

        # Verify command arguments
        assert "cicflowmeter" in cmd[0]
        assert "-i" in cmd
        assert "eth0" in cmd  # interface
        assert "-c" in cmd
        assert str(reader.cic_output_dir) in cmd
        assert "--rotate-rows" in cmd
        assert "1000" in cmd


def test_stream_csv_reads_data_and_puts_to_queue(mock_app_config, tmp_path):
    reader = Reader(mock_app_config, mode="live")
    reader.running = True

    # Setup directories
    cic_dir = tmp_path / "data" / "cic"
    cic_dir.mkdir(parents=True)
    reader.cic_output_dir = cic_dir

    upload_dir = tmp_path / "data" / "upload_queue"
    upload_dir.mkdir()
    reader.upload_queue_dir = upload_dir

    # Create dummy CSV file
    csv_file = cic_dir / "20240218_flow_data_0.csv"
    with open(csv_file, "w") as f:
        f.write("src_ip,dst_ip,protocol\n")  # Header
        f.write("192.168.1.1,8.8.8.8,TCP\n")  # Data 1
        f.write("10.0.0.1,1.1.1.1,UDP\n")  # Data 2

    # Mock _get_file_by_seq to simulate file discovery
    def mock_get_file(seq):
        if seq == 0 and csv_file.exists():
            return csv_file
        reader.running = False
        return None

    with patch.object(reader, "_get_file_by_seq", side_effect=mock_get_file):
        reader._stream_csv()

    # Assert Queue Data
    assert reader.raw_packet_queue.qsize() == 2
    item1 = reader.raw_packet_queue.get()
    assert item1["src_ip"] == "192.168.1.1"

    # Assert File Moved
    assert not csv_file.exists()
    assert (upload_dir / csv_file.name).exists()


def test_stream_csv_handles_missing_file_and_empty_lines(mock_app_config, tmp_path):
    """
    Test loop continuity:
    1. First loop: No file found (sleep -> continue)
    2. Second loop: File found, but has empty lines (continue)
    3. Third loop: Stop
    """
    reader = Reader(mock_app_config)
    reader.running = True
    reader.cic_output_dir = tmp_path
    reader.upload_queue_dir = tmp_path / "upload"
    reader.upload_queue_dir.mkdir()

    # Create CSV with empty lines
    csv_file = tmp_path / "0_flow_data_0.csv"
    with open(csv_file, "w") as f:
        f.write("col1,col2\n")  # Header
        f.write("\n")  # Empty line (should be skipped)
        f.write("val1,val2\n")  # Valid Data

    def mock_get_file_effect(seq):
        if seq == 0:
            # First call returns None
            if not hasattr(mock_get_file_effect, "called_once"):
                mock_get_file_effect.called_once = True
                return None
            # Second call returns file
            return csv_file
        # Break loop
        reader.running = False
        return None

    with (
        patch.object(reader, "_get_file_by_seq", side_effect=mock_get_file_effect),
        patch("time.sleep") as mock_sleep,  # Prevent actual sleeping
    ):
        reader._stream_csv()

    # Check that empty line was skipped
    assert reader.raw_packet_queue.qsize() == 1
    item = reader.raw_packet_queue.get()
    assert item["col1"] == "val1"

    mock_sleep.assert_called()


def test_wait_for_header_retries_on_empty_file(mock_app_config):
    """Test waiting logic when file exists but is initially empty."""
    reader = Reader(mock_app_config)
    reader.running = True

    f = MagicMock()
    # readline returns: "" (empty), then "header"
    f.readline.side_effect = ["", "col1,col2"]

    with patch("time.sleep") as mock_sleep:
        headers = reader._wait_for_header(f)

    assert headers == ["col1", "col2"]
    mock_sleep.assert_called_once()


def test_follow_file_switches_when_next_file_appears(mock_app_config):
    reader = Reader(mock_app_config)
    reader.running = True

    f = MagicMock()
    f.readline.return_value = ""  # Simulate EOF

    # Simulate next file appearing
    with patch.object(reader, "_get_file_by_seq", return_value=Path("next_file.csv")):
        generator = reader._follow_file(f, current_seq=0)

        # Should raise StopIteration immediately as next file is found
        with pytest.raises(StopIteration):
            next(generator)


def test_get_file_by_seq_returns_none_if_no_match(mock_app_config, tmp_path):
    reader = Reader(mock_app_config)
    reader.cic_output_dir = tmp_path

    # No matching files
    result = reader._get_file_by_seq(99)
    assert result is None


def test_get_file_by_seq_returns_latest_file_when_multiple_matches(
    mock_app_config, tmp_path
):
    reader = Reader(mock_app_config)
    reader.cic_output_dir = tmp_path

    # Create multiple matching files
    file1 = tmp_path / "20240218_flow_data_0.csv"
    file2 = tmp_path / "20240219_flow_data_0.csv"
    file1.touch()
    file2.touch()

    result = reader._get_file_by_seq(0)
    assert result == file2  # Should return the latest (sorted reverse)


def test_run_pcap_when_input_valid(mock_app_config, tmp_path):
    reader = Reader(mock_app_config, mode="pcap")
    pcap_file = tmp_path / "test.pcap"
    pcap_file.touch()

    with (
        patch("subprocess.run") as mock_run,
        patch.object(reader, "_read_csv_direct") as mock_read_csv,
    ):
        reader.start(input_file=pcap_file)

        mock_run.assert_called_once()
        mock_read_csv.assert_called_once()


def test_run_pcap_when_input_missing_raises_error(mock_app_config):
    reader = Reader(mock_app_config, mode="pcap")
    with pytest.raises(ValueError, match="PCAP path is required"):
        reader.start(input_file=None)


def test_run_csv_direct_reads_pandas_chunks(mock_app_config, tmp_path):
    reader = Reader(mock_app_config, mode="csv")
    csv_file = tmp_path / "test_dataset.csv"

    # Mock CSV data
    df = pd.DataFrame({"col1": range(10)})
    df.to_csv(csv_file, index=False)

    reader.start(input_file=csv_file)

    # (10 records + 1 None shutdown signal)
    assert reader.raw_packet_queue.qsize() == 11

    # Verify the last item
    items = []
    while not reader.raw_packet_queue.empty():
        items.append(reader.raw_packet_queue.get())

    assert items[-1] is None  # Shutdown signal


def test_read_csv_direct_handles_missing_file(mock_app_config):
    reader = Reader(mock_app_config)

    with patch("ddos_martummai.reader.logger") as mock_logger:
        reader._read_csv_direct(Path("ghost.csv"))

        mock_logger.error.assert_called_with("CSV not found: ghost.csv")


def test_read_csv_direct_stops_if_not_running(mock_app_config, tmp_path):
    reader = Reader(mock_app_config)
    csv_file = tmp_path / "test.csv"

    df = pd.DataFrame({"col": range(10)})
    df.to_csv(csv_file, index=False)

    reader.running = True

    # Mock pandas to return chunks, but stop reader before processing
    with patch("pandas.read_csv") as mock_read:
        mock_read.return_value = [pd.DataFrame({"col": range(5)})]

        reader.running = False
        reader._read_csv_direct(csv_file)

        # Queue should remain empty
        assert reader.raw_packet_queue.empty()


def test_prepare_uploader_when_disabled(mock_app_config):
    mock_app_config.system.google_drive_upload = False
    reader = Reader(mock_app_config)

    with patch("ddos_martummai.reader.logger") as mock_logger:
        reader._prepare_uploader()

        mock_logger.warning.assert_called()
        assert reader.uploader is None


def test_prepare_uploader_when_enabled_starts_uploader(mock_app_config, tmp_path):
    # Enable Config
    mock_app_config.system.google_drive_upload = True
    reader = Reader(mock_app_config)
    reader.upload_queue_dir = tmp_path / "upload_queue"

    with patch("ddos_martummai.reader.DriveUploader") as MockUploader:
        reader._prepare_uploader()

        MockUploader.assert_called_once()
        reader.uploader.start.assert_called_once()


def test_prepare_uploader_raises_validation_errors(mock_app_config, tmp_path):
    mock_app_config.system.google_drive_upload = True
    reader = Reader(mock_app_config)

    # Case 1: Upload Queue Dir not set
    reader.upload_queue_dir = None
    with pytest.raises(ValueError, match="Upload queue directory is not set"):
        reader._prepare_uploader()

    # Case 2: Token file missing
    reader.upload_queue_dir = tmp_path
    mock_app_config.system.token_file_path = ""
    with pytest.raises(ValueError, match="Token file path is not configured"):
        reader._prepare_uploader()

    # Case 3: Folder ID missing
    mock_app_config.system.token_file_path = "token.json"
    mock_app_config.system.google_drive_folder_id = ""
    with pytest.raises(ValueError, match="Google Drive folder ID is not configured"):
        reader._prepare_uploader()


def test_stop_calls_uploader_stop(mock_app_config):
    reader = Reader(mock_app_config)
    reader.uploader = MagicMock()

    with patch.object(reader, "_terminate_cic"):
        reader.stop()

        reader.uploader.stop.assert_called_once()


def test_stop_reader_process(mock_app_config):
    reader = Reader(mock_app_config)
    mock_process = MagicMock()
    reader.cic_process = mock_process

    reader.stop()

    assert reader.running is False
    mock_process.terminate.assert_called_once()
    mock_process.wait.assert_called_once()


def test_terminates_cic_process_but_no_process(mock_app_config):
    reader = Reader(mock_app_config)
    reader.cic_process = None

    with patch("ddos_martummai.reader.logger") as mock_logger:
        reader._terminate_cic()
        mock_logger.info.assert_not_called()  # No process, so no termination log


def test_terminate_cic_kills_process_on_timeout(mock_app_config):
    reader = Reader(mock_app_config)
    mock_process = MagicMock()
    mock_process.wait.side_effect = subprocess.TimeoutExpired(cmd="cmd", timeout=2)
    reader.cic_process = mock_process

    reader._terminate_cic()

    mock_process.terminate.assert_called_once()
    mock_process.kill.assert_called_once()


def test_move_to_upload_queue_handles_exception(mock_app_config, tmp_path):
    reader = Reader(mock_app_config)
    reader.upload_queue_dir = tmp_path

    src = tmp_path / "src.csv"
    src.touch()

    with (
        patch("shutil.move", side_effect=OSError("Permission denied")),
        patch("ddos_martummai.reader.logger") as mock_logger,
    ):
        reader._move_to_upload_queue(src)

        mock_logger.error.assert_called()
        assert "Permission denied" in mock_logger.error.call_args[0][0]


def test_move_to_upload_queue_when_directory_none(mock_app_config):
    reader = Reader(mock_app_config)
    reader.upload_queue_dir = None

    # Should not raise any error
    reader._move_to_upload_queue(Path("file.csv"))
