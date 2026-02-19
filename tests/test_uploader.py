from unittest.mock import MagicMock, patch

import pytest
from googleapiclient.errors import HttpError

from ddos_martummai.drive_uploader import DriveUploader

# FIXTURES


@pytest.fixture
def temp_dirs(tmp_path):
    upload_folder = tmp_path / "uploads"
    token_file = tmp_path / "token.json"
    return upload_folder, token_file


@pytest.fixture
def uploader(temp_dirs):
    upload_folder, token_file = temp_dirs
    return DriveUploader(
        upload_folder=upload_folder,
        token_file=token_file,
        drive_folder_id="mock_folder_id",
    )


# INIT & THREAD CONTROL TESTS


def test_init_creates_upload_folder(temp_dirs):
    upload_folder, token_file = temp_dirs
    assert not upload_folder.exists()

    DriveUploader(upload_folder, token_file, "folder_id")
    assert upload_folder.exists()


def test_start_and_stop(uploader):
    with patch("ddos_martummai.drive_uploader.threading.Thread") as mock_thread:
        # Test the start sequence
        uploader.start()
        assert not uploader._stop_event.is_set()

        # Verify that the thread is created with _worker_loop and started
        mock_thread.assert_called_once_with(target=uploader._worker_loop, daemon=True)
        mock_thread.return_value.start.assert_called_once()

        # Test the stop sequence
        uploader.stop()
        assert uploader._stop_event.is_set()

        # Verify that the thread is joined (waited to finish)
        mock_thread.return_value.join.assert_called_once()


# AUTHENTICATION


def test_connect_drive_no_token_file(uploader):
    # Should return False if the token file does not exist
    assert not uploader.token_file.exists()
    assert uploader._connect_drive() is False


def test_connect_drive_valid_token(uploader):
    # Should return True and build the service when a valid token is provided
    uploader.token_file.write_text('{"token": "mock_token"}')

    with (
        patch("ddos_martummai.drive_uploader.Credentials") as mock_creds_class,
        patch("ddos_martummai.drive_uploader.build") as mock_build,
    ):
        mock_creds_instance = MagicMock()
        mock_creds_instance.valid = True
        mock_creds_class.from_authorized_user_file.return_value = mock_creds_instance

        result = uploader._connect_drive()

        assert result is True
        assert uploader.service is not None
        mock_build.assert_called_once_with(
            "drive", "v3", credentials=mock_creds_instance
        )


def test_connect_drive_expired_token_refresh_success(uploader):
    # Should refresh the token and save the new one if it is expired but has a refresh token
    uploader.token_file.write_text('{"token": "old_token"}')
    with (
        patch("ddos_martummai.drive_uploader.Credentials") as mock_creds_class,
        patch("ddos_martummai.drive_uploader.build"),
    ):
        mock_creds_instance = MagicMock()
        mock_creds_instance.valid = False
        mock_creds_instance.expired = True
        mock_creds_instance.refresh_token = "some_refresh_token"
        mock_creds_instance.to_json.return_value = '{"new": "token"}'
        mock_creds_class.from_authorized_user_file.return_value = mock_creds_instance

        result = uploader._connect_drive()

        assert result is True
        mock_creds_instance.refresh.assert_called_once()

        # Verify that the token file is overwritten with the new token
        assert uploader.token_file.read_text() == '{"new": "token"}'


def test_connect_drive_invalid_unrefreshable_token(uploader):
    # Should return False if the token is invalid and cannot be refreshed
    with patch("ddos_martummai.drive_uploader.Credentials") as mock_creds_class:
        mock_creds_instance = MagicMock()
        mock_creds_instance.valid = False
        mock_creds_instance.expired = True
        mock_creds_instance.refresh_token = None
        mock_creds_class.from_authorized_user_file.return_value = mock_creds_instance

        result = uploader._connect_drive()

        assert result is False
        assert uploader.service is None


# UPLOAD LOGIC


def test_upload_to_drive_success(uploader, tmp_path):
    # Should return True when the upload is successful and an ID is returned
    with patch("ddos_martummai.drive_uploader.MediaFileUpload"):
        csv_file = tmp_path / "test.csv"
        csv_file.touch()

        # Mock the Drive API service
        uploader.service = MagicMock()
        mock_files = uploader.service.files.return_value
        mock_create = mock_files.create.return_value
        mock_create.execute.return_value = {"id": "new_file_id"}

        result = uploader._upload_to_drive(csv_file)

        assert result is True
        mock_files.create.assert_called_once()
        assert mock_files.create.call_args[1]["body"]["name"] == "test.csv"
        assert mock_files.create.call_args[1]["body"]["parents"] == ["mock_folder_id"]


def test_upload_to_drive_http_error(uploader, tmp_path):
    # Should drop the service and return False if a Google API HttpError occurs
    with patch("ddos_martummai.drive_uploader.MediaFileUpload"):
        csv_file = tmp_path / "test.csv"
        csv_file.touch()

        uploader.service = MagicMock()
        mock_create = uploader.service.files.return_value.create.return_value

        # Mock the HttpError
        resp = MagicMock(status=403)
        mock_create.execute.side_effect = HttpError(resp, b"Forbidden")

        result = uploader._upload_to_drive(csv_file)

        assert result is False
        assert uploader.service is None


def test_upload_to_drive_auto_reconnect(uploader, tmp_path):
    # Should attempt to auto-reconnect if the service is missing
    csv_file = tmp_path / "test.csv"
    csv_file.touch()
    uploader.service = None

    with patch.object(uploader, "_connect_drive", return_value=False) as mock_connect:
        result = uploader._upload_to_drive(csv_file)

        mock_connect.assert_called_once()
        assert result is False


# WORKER LOOP INTEGRATION


def test_worker_loop_upload_success_and_delete(uploader):
    # Worker loop flow: finds file -> uploads successfully -> deletes file -> stops
    csv_file = uploader.upload_folder / "data.csv"
    csv_file.write_text("dummy")

    uploader.service = MagicMock()

    # Mock a successful upload and immediately set the stop event to break the loop
    def mock_upload_effect(file_path):
        uploader._stop_event.set()
        return True

    with patch.object(
        uploader, "_upload_to_drive", side_effect=mock_upload_effect
    ) as mock_upload:
        uploader._worker_loop()

        mock_upload.assert_called_once_with(csv_file)
        assert not csv_file.exists()


def test_worker_loop_upload_fails_retry(uploader):
    # Worker loop flow: finds file -> upload fails -> keeps file -> retries
    csv_file = uploader.upload_folder / "data.csv"
    csv_file.write_text("dummy")

    uploader.service = MagicMock()

    # Intercept the wait() call to break the loop safely during tests
    def mock_wait_effect(timeout):
        uploader._stop_event.set()
        return True

    with (
        patch.object(uploader, "_upload_to_drive", return_value=False),
        patch.object(
            uploader._stop_event, "wait", side_effect=mock_wait_effect
        ) as mock_wait,
    ):
        uploader._worker_loop()

        # The file should not be deleted
        assert csv_file.exists()
        # Should wait for 60 seconds before retrying
        mock_wait.assert_called_once_with(60)


def test_worker_loop_file_delete_error(uploader, caplog):
    # Should not crash if the file is uploaded but the OS denies deletion (OSError)
    csv_file = uploader.upload_folder / "data.csv"
    csv_file.write_text("dummy")
    uploader.service = MagicMock()

    def mock_upload_effect(file_path):
        uploader._stop_event.set()
        return True

    with (
        patch.object(uploader, "_upload_to_drive", side_effect=mock_upload_effect),
        patch("pathlib.Path.unlink", side_effect=OSError("Permission Denied")),
    ):
        uploader._worker_loop()

        assert "Error deleting file data.csv: Permission Denied" in caplog.text


# EDGE CASES & EXCEPTION HANDLING TESTS


def test_stop_without_start(uploader):
    # Should handle stop() gracefully even if start() was never called
    uploader.stop()
    assert uploader._stop_event.is_set()
    assert uploader._thread is None


def test_connect_drive_refresh_token_exception(uploader, caplog):
    # Should return False and log a fatal error if the token refresh process raises an exception
    uploader.token_file.write_text('{"token": "old_token"}')

    with patch("ddos_martummai.drive_uploader.Credentials") as mock_creds_class:
        mock_creds = MagicMock()
        mock_creds.valid = False
        mock_creds.expired = True
        mock_creds.refresh_token = "yes"
        mock_creds.refresh.side_effect = Exception("Refresh Boom")
        mock_creds_class.from_authorized_user_file.return_value = mock_creds

        assert uploader._connect_drive() is False
        assert "FATAL: Failed to refresh token: Refresh Boom" in caplog.text


def test_connect_drive_general_exception(uploader, caplog):
    # Should return False and log a fatal error if authentication raises a general exception
    uploader.token_file.write_text('{"token": "mock_token"}')

    with patch("ddos_martummai.drive_uploader.Credentials") as mock_creds_class:
        mock_creds_class.from_authorized_user_file.side_effect = Exception("Auth Boom")

        assert uploader._connect_drive() is False
        assert "FATAL: Authentication Error: Auth Boom" in caplog.text


def test_connect_drive_invalid_when_expired_but_no_refresh_token(uploader, caplog):
    uploader.token_file.write_text('{"token": "old"}')

    with patch("ddos_martummai.drive_uploader.Credentials") as mock_creds_class:
        mock_creds = MagicMock()
        mock_creds.valid = False
        mock_creds.expired = True
        mock_creds.refresh_token = None
        mock_creds_class.from_authorized_user_file.return_value = mock_creds

        assert uploader._connect_drive() is False
        assert "FATAL: Token is invalid and cannot be refreshed." in caplog.text


def test_worker_loop_initial_auth_failure(uploader, caplog):
    # Should abort the worker loop immediately if initial authentication fails
    uploader.service = None
    with patch.object(uploader, "_connect_drive", return_value=False):
        uploader._worker_loop()
        assert "Uploader Service Aborted due to Auth failure." in caplog.text


def test_worker_loop_stop_event_during_file_iteration(uploader):
    # Should stop processing files if the stop event is set during the file iteration
    csv_file1 = uploader.upload_folder / "data1.csv"
    csv_file1.write_text("1")
    uploader.service = MagicMock()

    # 1st call (while loop): False (enter loop)
    # 2nd call (for loop): True (break out of file processing)
    # 3rd call (while loop again): True (exit loop completely)
    with patch.object(uploader._stop_event, "is_set", side_effect=[False, True, True]):
        uploader._worker_loop()

    # File should not be uploaded or deleted
    assert csv_file1.exists()


def test_worker_loop_reconnect_fails_during_upload(uploader, caplog):
    # Should stop the worker if the service drops and reconnection fails during file processing
    csv_file = uploader.upload_folder / "data.csv"
    csv_file.write_text("dummy")

    # Set a mock service initially to pass the first auth check
    uploader.service = MagicMock()

    # Trick: Clear the service during the is_set() check to simulate a lost connection
    def mock_is_set_effect():
        uploader.service = None
        return False

    with (
        patch.object(uploader._stop_event, "is_set", side_effect=mock_is_set_effect),
        patch.object(uploader, "_connect_drive", return_value=False),
        # Return True on wait() to break the retry loop
        patch.object(uploader._stop_event, "wait", return_value=True),
    ):
        uploader._worker_loop()

    assert "Lost connection and cannot recover. Worker stopping." in caplog.text


def test_worker_loop_no_files_waits(uploader):
    # Should wait for 5 seconds and loop again if no CSV files are found

    # 1. Mock the service to pass the auth check
    uploader.service = MagicMock()

    # Note: We intentionally do not create any .csv files to trigger the 'if not files' condition.

    # 2. Intercept wait(5) to prevent the test from hanging, and stop the loop
    def mock_wait_effect(timeout):
        uploader._stop_event.set()
        return True

    with patch.object(
        uploader._stop_event, "wait", side_effect=mock_wait_effect
    ) as mock_wait:
        uploader._worker_loop()

        # 3. Verify that wait(5) was called
        mock_wait.assert_called_once_with(5)


def test_upload_to_drive_no_id_returned(uploader, tmp_path):
    # Should return False if the Google API succeeds but does not return a file ID
    csv_file = tmp_path / "test.csv"
    csv_file.touch()
    uploader.service = MagicMock()

    with patch("ddos_martummai.drive_uploader.MediaFileUpload"):
        mock_create = uploader.service.files.return_value.create.return_value
        # Simulate a response missing the 'id' key
        mock_create.execute.return_value = {}

        assert uploader._upload_to_drive(csv_file) is False


def test_upload_to_drive_general_exception_unauthorized(uploader, tmp_path, caplog):
    # Should drop the service (set to None) if a general exception containing 'Unauthorized' occurs
    csv_file = tmp_path / "test.csv"
    csv_file.touch()
    uploader.service = MagicMock()

    with patch(
        "ddos_martummai.drive_uploader.MediaFileUpload",
        side_effect=Exception("Error: Unauthorized token"),
    ):
        assert uploader._upload_to_drive(csv_file) is False
        assert uploader.service is None
        assert "Network/General Error: Error: Unauthorized token" in caplog.text


def test_upload_to_drive_general_exception_other(uploader, tmp_path, caplog):
    # Should not drop the service for a general exception (e.g., network timeout) unrelated to auth
    csv_file = tmp_path / "test.csv"
    csv_file.touch()
    uploader.service = MagicMock()

    with patch(
        "ddos_martummai.drive_uploader.MediaFileUpload",
        side_effect=Exception("Connection Timeout"),
    ):
        assert uploader._upload_to_drive(csv_file) is False
        assert uploader.service is not None
        assert "Network/General Error: Connection Timeout" in caplog.text
