import subprocess
from multiprocessing import Event, Queue
from pathlib import Path
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


@pytest.fixture
def mock_queue():
    return Queue()


@pytest.fixture
def mock_stop_event():
    return Event()


@pytest.fixture
def reader(mock_app_config, mock_queue, mock_stop_event):
    """Fixture หลักที่พร้อมใช้งานในทุก Test Case"""
    return Reader(
        config=mock_app_config,
        raw_packet_queue=mock_queue,
        stop_event=mock_stop_event,
        mode="live",
    )


# ==========================================
# Test Cases
# ==========================================


def test_init_when_valid_config(reader, mock_app_config):
    assert reader.config == mock_app_config
    assert reader.mode == "live"
    assert not reader.stop_event.is_set()
    assert hasattr(reader.raw_packet_queue, "put")


def test_start_when_mode_is_live_calls_run_live(reader):
    with patch.object(reader, "_run_live") as mock_run_live:
        reader.start()

        mock_run_live.assert_called_once()
        assert reader.raw_packet_queue.get(timeout=1) is None


def test_start_when_unknown_mode_raises_error(reader):
    reader.mode = "AraiWah"

    with pytest.raises(ValueError, match="Unknown mode: AraiWah"):
        reader.start()

    # If an error occurs, the queue should still receive the shutdown signal
    assert reader.raw_packet_queue.get(timeout=1) is None


def test_run_live_flow_execution(reader):
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


def test_prepare_csv_output_creates_directories_and_cleans_old_files(reader, tmp_path):
    # Setup directories and mock files
    data_path = tmp_path / "output"
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

    # Assertions for file cleaning
    assert not file_to_delete.exists()
    assert file_to_keep.exists()


def test_start_cicflowmeter_live_builds_correct_command(reader):
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
        assert "eth0" in cmd
        assert "-c" in cmd
        assert str(reader.cic_output_dir) in cmd
        assert "--rotate-rows" in cmd
        assert "1000" in cmd


def test_stream_csv_reads_data_and_puts_to_queue(reader, tmp_path):
    cic_dir = tmp_path / "data" / "cic"
    cic_dir.mkdir(parents=True)
    reader.cic_output_dir = cic_dir

    upload_dir = tmp_path / "data" / "upload_queue"
    upload_dir.mkdir()
    reader.upload_queue_dir = upload_dir

    # 1. Create the first CSV file (seq = 0) with our actual test data
    csv_file_0 = cic_dir / "20240218_flow_data_0.csv"
    with open(csv_file_0, "w") as f:
        f.write("src_ip,dst_ip,protocol\n")
        f.write("192.168.1.1,8.8.8.8,TCP\n")
        f.write("10.0.0.1,1.1.1.1,UDP\n")

    # 2. Create a second dummy CSV file (seq = 1).
    # The reader needs to see this next file to realize that the first file is completely finished.
    csv_file_1 = cic_dir / "20240218_flow_data_1.csv"
    with open(csv_file_1, "w") as f:
        f.write("src_ip,dst_ip,protocol\n")  # Just headers, no data

    # 3. Define a mock behavior for finding CSV files sequentially.
    def mock_get_file(seq):
        if seq == 0:
            return csv_file_0
        if seq == 1:
            return csv_file_1
        return (
            None  # Return None for seq 2 and beyond to simulate waiting for new files
        )

    # 4. Replace the real file-finding method with our mock
    with patch.object(reader, "_get_file_by_seq", side_effect=mock_get_file):
        # The reader will finish file 0, move it to upload_queue, and start file 1.
        # When it reaches the end of file 1, it will look for file 2 (which is None).
        # It will then call time.sleep() to wait. We intercept this sleep to stop the test safely!
        with patch("time.sleep", side_effect=lambda x: reader.stop_event.set()):
            reader._stream_csv()

    # Assert Queue Data
    # It should only contain the 2 records from csv_file_0
    assert reader.raw_packet_queue.qsize() == 2
    item1 = reader.raw_packet_queue.get()
    assert item1["src_ip"] == "192.168.1.1"

    # Assert File Moved
    # csv_file_0 should now be successfully moved to the upload directory
    assert not csv_file_0.exists()
    assert (upload_dir / csv_file_0.name).exists()


def test_stream_csv_handles_missing_file_and_empty_lines(reader, tmp_path):
    reader.cic_output_dir = tmp_path
    reader.upload_queue_dir = tmp_path / "upload"
    reader.upload_queue_dir.mkdir()

    csv_file = tmp_path / "0_flow_data_0.csv"
    with open(csv_file, "w") as f:
        f.write("col1,col2\n")
        f.write("\n")
        f.write("val1,val2\n")

    def mock_get_file_effect(seq):
        if seq == 0:
            if not hasattr(mock_get_file_effect, "called_once"):
                mock_get_file_effect.called_once = True
                return None
            return csv_file
        reader.stop_event.set()
        return None

    with (
        patch.object(reader, "_get_file_by_seq", side_effect=mock_get_file_effect),
        patch("time.sleep") as mock_sleep,
    ):
        reader._stream_csv()

    assert reader.raw_packet_queue.qsize() == 1
    item = reader.raw_packet_queue.get()
    assert item["col1"] == "val1"
    mock_sleep.assert_called()


def test_wait_for_header_retries_on_empty_file(reader):
    f = MagicMock()
    f.readline.side_effect = ["", "col1,col2"]

    with patch("time.sleep") as mock_sleep:
        headers = reader._wait_for_header(f)

    assert headers == ["col1", "col2"]
    mock_sleep.assert_called_once()


def test_follow_file_switches_when_next_file_appears(reader):
    f = MagicMock()
    f.readline.return_value = ""

    with patch.object(reader, "_get_file_by_seq", return_value=Path("next_file.csv")):
        generator = reader._follow_file(f)

        with pytest.raises(StopIteration):
            next(generator)


def test_get_file_by_seq_returns_latest_file(reader, tmp_path):
    reader.cic_output_dir = tmp_path

    # No matching files
    assert reader._get_file_by_seq(99) is None

    # Check case when multiple files exist, should return the latest file
    file1 = tmp_path / "20240218_flow_data_0.csv"
    file2 = tmp_path / "20240219_flow_data_0.csv"
    file1.touch()
    file2.touch()

    result = reader._get_file_by_seq(0)
    assert result == file2  # Should return the latest (sorted reverse)


def test_run_pcap_when_input_valid(reader, tmp_path):
    reader.mode = "pcap"
    pcap_file = tmp_path / "test.pcap"
    pcap_file.touch()

    with (
        patch("subprocess.run") as mock_run,
        patch.object(reader, "_read_csv_direct") as mock_read_csv,
    ):
        reader.start(input_file=pcap_file)

        mock_run.assert_called_once()
        mock_read_csv.assert_called_once()


def test_run_pcap_when_input_missing_raises_error(reader):
    reader.mode = "pcap"
    with pytest.raises(ValueError, match="PCAP path is required"):
        reader.start(input_file=None)


def test_run_csv_direct_reads_pandas_chunks(reader, tmp_path):
    csv_file = tmp_path / "test_dataset.csv"
    df = pd.DataFrame({"col1": range(10)})
    df.to_csv(csv_file, index=False)

    reader._read_csv_direct(csv_file)

    assert reader.raw_packet_queue.qsize() == 10

    # Verify the last item
    items = []
    for _ in range(10):
        items.append(reader.raw_packet_queue.get(timeout=1))

    assert items[-1]["col1"] == 9


def test_read_csv_direct_handles_missing_file(reader):
    with patch("ddos_martummai.reader.logger") as mock_logger:
        reader._read_csv_direct(Path("ghost.csv"))
        mock_logger.error.assert_called_with("CSV not found: ghost.csv")


def test_read_csv_direct_stops_if_event_is_set(reader, tmp_path):
    csv_file = tmp_path / "test.csv"
    df = pd.DataFrame({"col": range(10)})
    df.to_csv(csv_file, index=False)

    with patch("pandas.read_csv") as mock_read:
        mock_read.return_value = [pd.DataFrame({"col": range(5)})]

        # Set Event to stop before reading any Chunk
        reader.stop_event.set()
        reader._read_csv_direct(csv_file)

        assert reader.raw_packet_queue.empty()


def test_prepare_uploader_when_disabled(reader, mock_app_config):
    mock_app_config.system.google_drive_upload = False

    with patch("ddos_martummai.reader.logger") as mock_logger:
        reader._prepare_uploader()

        mock_logger.warning.assert_called()
        assert reader.uploader is None


def test_prepare_uploader_when_enabled_starts_uploader(
    reader, mock_app_config, tmp_path
):
    mock_app_config.system.google_drive_upload = True
    reader.upload_queue_dir = tmp_path / "upload_queue"

    with patch("ddos_martummai.reader.DriveUploader") as MockUploader:
        reader._prepare_uploader()

        MockUploader.assert_called_once()
        reader.uploader.start.assert_called_once()


def test_prepare_uploader_raises_validation_errors(reader, mock_app_config, tmp_path):
    mock_app_config.system.google_drive_upload = True

    reader.upload_queue_dir = None
    with pytest.raises(ValueError, match="Upload queue directory is not set"):
        reader._prepare_uploader()

    reader.upload_queue_dir = tmp_path
    mock_app_config.system.token_file_path = ""
    with pytest.raises(ValueError, match="Token file path is not configured"):
        reader._prepare_uploader()

    mock_app_config.system.token_file_path = "token.json"
    mock_app_config.system.google_drive_folder_id = ""
    with pytest.raises(ValueError, match="Google Drive folder ID is not configured"):
        reader._prepare_uploader()


def test_stop_calls_uploader_stop(reader):
    reader.uploader = MagicMock()
    with patch.object(reader, "_terminate_cic"):
        reader.stop()
        reader.uploader.stop.assert_called_once()


def test_stop_reader_process(reader):
    mock_process = MagicMock()
    reader.cic_process = mock_process

    reader.stop()

    mock_process.terminate.assert_called_once()
    mock_process.wait.assert_called_once()


def test_terminates_cic_process_but_no_process(reader):
    reader.cic_process = None
    with patch("ddos_martummai.reader.logger") as mock_logger:
        reader._terminate_cic()
        mock_logger.info.assert_not_called()


def test_terminate_cic_kills_process_on_timeout(reader):
    mock_process = MagicMock()
    mock_process.wait.side_effect = subprocess.TimeoutExpired(cmd="cmd", timeout=2)
    reader.cic_process = mock_process

    reader._terminate_cic()

    mock_process.terminate.assert_called_once()
    mock_process.kill.assert_called_once()


def test_move_to_upload_queue_handles_exception(reader, tmp_path):
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


def test_move_to_upload_queue_when_directory_none(reader):
    reader.upload_queue_dir = None

    # Should not raise any error
    reader._move_to_upload_queue(Path("file.csv"))
