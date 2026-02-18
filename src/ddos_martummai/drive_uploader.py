import logging
import threading
from pathlib import Path
from typing import Optional

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import Resource, build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaFileUpload

logger = logging.getLogger("UPLOADER")


class DriveUploader:
    SCOPES = ["https://www.googleapis.com/auth/drive.file"]

    def __init__(self, upload_folder: Path, token_file: Path, drive_folder_id: str):
        self.upload_folder: Path = upload_folder
        self.token_file: Path = token_file
        self.drive_folder_id: str = drive_folder_id

        self.upload_folder.mkdir(exist_ok=True)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self.service: Optional[Resource] = None

    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join()

    def _connect_drive(self) -> bool:
        creds = None
        try:
            if self.token_file.exists():
                creds = Credentials.from_authorized_user_file(
                    self.token_file, self.SCOPES
                )
            else:
                logger.critical(f"FATAL: '{self.token_file}' not found!")
                return False

            if not creds.valid:
                if creds.expired and creds.refresh_token:
                    try:
                        logger.info("Token expired. Refreshing...")
                        creds.refresh(Request())
                        with open(self.token_file, "w") as token:
                            token.write(creds.to_json())
                    except Exception as e:
                        logger.critical(f"FATAL: Failed to refresh token: {e}")
                        return False
                else:
                    logger.critical("FATAL: Token is invalid and cannot be refreshed.")
                    return False

            self.service = build("drive", "v3", credentials=creds)
            logger.info("Connected to Google Drive successfully.")
            return True

        except Exception as e:
            logger.critical(f"FATAL: Authentication Error: {e}")
            return False

    def _worker_loop(self):
        logger.info("Uploader worker started...")

        if not self.service:
            if not self._connect_drive():
                logger.critical("Uploader Service Aborted due to Auth failure.")
                return

        while not self._stop_event.is_set():
            files = sorted(list(self.upload_folder.glob("*.csv")))

            if not files:
                self._stop_event.wait(5)
                continue

            upload_error_occurred = False

            for file_path in files:
                if self._stop_event.is_set():
                    break

                if self.service is None:
                    if not self._connect_drive():
                        logger.critical(
                            "Lost connection and cannot recover. Worker stopping."
                        )
                        upload_error_occurred = True
                        break

                logger.info(f"Uploading: {file_path.name}")
                success = self._upload_to_drive(file_path)

                if success:
                    try:
                        file_path.unlink()
                        logger.info(f"Uploaded & Deleted: {file_path.name}")
                    except OSError as e:
                        logger.error(f"Error deleting file {file_path.name}: {e}")
                else:
                    upload_error_occurred = True
                    break

            if upload_error_occurred:
                logger.error("Upload failed. Retrying in 1 minute...")
                if self._stop_event.wait(60):
                    break
            else:
                self._stop_event.wait(1)

        logger.info("Uploader worker stopped.")

    def _upload_to_drive(self, file_path: Path) -> bool:
        try:
            # Re-connect if service is missing
            if self.service is None:
                if not self._connect_drive():
                    return False

            file_metadata = {"name": file_path.name, "parents": [self.drive_folder_id]}

            media = MediaFileUpload(str(file_path), mimetype="text/csv", resumable=True)

            file = (
                self.service.files()  # type: ignore
                .create(body=file_metadata, media_body=media, fields="id")
                .execute()
            )

            if file.get("id"):
                return True
            return False

        except HttpError as error:
            logger.error(f"Google API Error: {error}")
            self.service = None
            return False
        except Exception as e:
            logger.error(f"Network/General Error: {e}")
            if "invalid_grant" in str(e) or "Unauthorized" in str(e):
                self.service = None
            return False
