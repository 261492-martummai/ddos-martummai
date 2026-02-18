import logging
import os
import re
import shutil
import subprocess  # nosec B404
import sys
import time
from pathlib import Path
from queue import Queue
from typing import Optional

import pandas as pd

from ddos_martummai.drive_uploader import DriveUploader
from ddos_martummai.init_models import AppConfig

logger = logging.getLogger("READER")


class Reader:
    def __init__(self, config: AppConfig, mode: str = "live"):
        self.config = config
        self.mode = mode
        self.running = False
        self.cic_process: Optional[subprocess.Popen] = None
        self.raw_packet_queue: Queue[dict | None] = Queue()
        self.cic_output_dir: Optional[Path] = None
        self.upload_queue_dir: Optional[Path] = None
        self.uploader: Optional[DriveUploader] = None

    def get_queue(self) -> Queue[dict | None]:
        return self.raw_packet_queue

    # ---------- Public API ----------

    def start(self, input_file: Optional[Path] = None):
        logger.info("Reader Started")
        self.running = True

        try:
            if self.mode == "live":
                self._run_live()
            elif self.mode == "pcap":
                self._run_pcap(input_file)
            elif self.mode == "csv":
                self._read_csv_direct(input_file)
            else:
                raise ValueError(f"Unknown mode: {self.mode}")
        finally:
            self._sent_shutdown_signal()

    def stop(self):
        logger.info("Stopping Reader...")
        self.running = False
        self._terminate_cic()
        if self.uploader:
            self.uploader.stop()

    # ---------- Mode Handlers ----------

    def _run_live(self):
        data_path = Path(self.config.system.csv_output_path)
        self._prepare_csv(data_path)
        self._prepare_uploader()
        self._start_cicflowmeter_live()
        self._stream_csv()

    def _run_pcap(self, pcap_path: Optional[Path]):
        if not pcap_path:
            raise ValueError("PCAP path is required")

        output_csv = Path(self.config.system.test_mode_output_path)
        output_csv.parent.mkdir(parents=True, exist_ok=True)

        cmd = self._build_cic_cmd("-f", pcap_path, output_csv)
        subprocess.run(cmd, check=True)  # nosec B603

        logger.info("PCAP conversion complete")
        self._read_csv_direct(output_csv)

    # ---------- CICFlowMeter ----------

    def _start_cicflowmeter_live(self):
        cmd = self._build_cic_cmd(
            "-i", self.config.system.interface, self.cic_output_dir
        )

        if self.config.system.csv_rotation_rows:
            cmd.extend(["--rotate-rows", str(self.config.system.csv_rotation_rows)])

        self.cic_process = subprocess.Popen(cmd)  # nosec B603
        logger.info("CICFlowMeter started")

    def _terminate_cic(self):
        if not self.cic_process:
            return

        logger.info("Terminating CICFlowMeter...")
        self.cic_process.terminate()
        try:
            self.cic_process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.cic_process.kill()
        logger.info("CICFlowMeter terminated")

    def _build_cic_cmd(self, flag, source, output):
        cic_exec = os.path.join(os.path.dirname(sys.executable), "cicflowmeter")
        return [cic_exec, flag, str(source), "-c", str(output)]

    # ---------- CSV Handling ----------

    def _prepare_csv(self, data_path: Path):
        data_path.mkdir(exist_ok=True)

        cic_out = data_path / "cic"
        cic_out.mkdir(exist_ok=True)
        self.cic_output_dir = cic_out

        queue_path = data_path / "upload_queue"
        queue_path.mkdir(exist_ok=True)
        self.upload_queue_dir = queue_path

        pattern = re.compile(r"^\d+_\d+_flow_data_\d+\.csv$")
        for item in cic_out.iterdir():
            if item.is_file() and pattern.match(item.name):
                item.unlink()

    def _prepare_uploader(self):
        if not self.config.system.google_drive_upload:
            logger.warning(
                "Google Drive upload is disabled. flow data will not be uploaded."
            )
            logger.warning(
                "To enable Google Drive upload, set 'google_drive_upload' to 'true' in the configuration file."
            )
            logger.warning(
                "and configure 'google_drive_folder_id' in the configuration file."
            )
            logger.warning(
                f"ensure your 'google-drive-token.json' file is correctly configured at {self.config.system.token_file_path}"
            )
            logger.warning(
                f"Flow data will be stored locally in the {self.upload_queue_dir} directory."
            )
            return

        if self.upload_queue_dir is None:
            raise ValueError("Upload queue directory is not set")

        if not self.config.system.token_file_path:
            raise ValueError(
                "Token file path is not configured for Google Drive upload"
            )

        if not self.config.system.google_drive_folder_id:
            raise ValueError("Google Drive folder ID is not configured for upload")

        self.uploader = DriveUploader(
            upload_folder=self.upload_queue_dir,
            token_file=Path(self.config.system.token_file_path),
            drive_folder_id=self.config.system.google_drive_folder_id,
        )
        self.uploader.start()

    def _stream_csv(self):
        current_seq = 0
        logger.info(f"Starting CSV stream from Sequence {current_seq}...")

        while self.running:
            csv_path = self._get_file_by_seq(current_seq)

            if not csv_path:
                time.sleep(0.5)
                continue

            logger.info(f"Processing file: {csv_path.name}")

            with open(csv_path, "r") as f:
                headers = self._wait_for_header(f)
                for line in self._follow_file(f, current_seq):
                    if not line.strip():
                        continue

                    record = line.strip().split(",")
                    if len(record) == len(headers):
                        self.raw_packet_queue.put(dict(zip(headers, record)))

            logger.info(f"Finished file {current_seq}, moving to next.")
            self._move_to_upload_queue(csv_path)
            current_seq += 1

    def _wait_for_header(self, file):
        logger.debug("Waiting for feature headers...")
        while self.running:
            line = file.readline()
            if line.strip():
                logger.debug("Headers detected")
                return line.strip().split(",")
            time.sleep(0.3)

    def _follow_file(self, file, current_seq):
        while self.running:
            line = file.readline()
            if line:
                yield line
            else:
                next_seq = current_seq + 1
                if self._get_file_by_seq(next_seq):
                    break
                time.sleep(0.3)

    def _get_file_by_seq(self, seq):
        pattern = f"*_flow_data_{seq}.csv"
        found_files = list(self.cic_output_dir.glob(pattern))

        if found_files:
            found_files.sort(reverse=True)
            return found_files[0]
        return None

    def _read_csv_direct(self, csv_path: Optional[Path]):
        if not csv_path or not csv_path.exists():
            logger.error(f"CSV not found: {csv_path}")
            return

        logger.info(f"Reading CSV: {csv_path}")

        for chunk in pd.read_csv(csv_path, chunksize=5000):
            if not self.running:
                break

            for record in chunk.to_dict(orient="records"):
                self.raw_packet_queue.put(record)

        logger.info("Finished CSV reading")

    def _move_to_upload_queue(self, file_path: Path):
        if self.upload_queue_dir is None:
            return

        try:
            destination = self.upload_queue_dir / file_path.name
            shutil.move(str(file_path), str(destination))
            logger.info(f"Moved {file_path.name} to upload queue.")

        except Exception as e:
            logger.error(f"Failed to move file to upload queue: {e}")

    # ---------- Shutdown ----------

    def _sent_shutdown_signal(self):
        self.raw_packet_queue.put(None)
        logger.info("Reader stopped")
