import logging
import subprocess  # nosec B404
import time
from pathlib import Path
import pandas as pd
from queue import Queue
from typing import Optional

import pandas as pd

from ddos_martummai.init_models import AppConfig

logger = logging.getLogger("READER")


class Reader:
    def __init__(self, config: AppConfig, mode: str = "live"):
        self.config = config
        self.raw_packet_queue: Queue[dict | None] = Queue()
        self.mode = mode
        self.running = False
        self.cic_process = None

    def get_queue(self) -> Queue[dict | None]:
        return self.raw_packet_queue

    def start(self, input_file: Optional[Path] = None):
        self.running = True

        if self.mode == "live":
            self._run_cicflowmeter_live()
        elif self.mode == "pcap":
            self._run_cicflowmeter_pcap(input_file)
        elif self.mode == "csv":
            self._read_csv_direct(input_file)

        # Stop signal
        logger.info("Reader Stopping...")
        self.raw_packet_queue.put(None)
        logger.info("Reader Stopped.")

    def stop(self):
        self.running = False
        if self.cic_process:
            logger.info("Terminating CICFlowMeter process...")
            self.cic_process.terminate()
            try:
                self.cic_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.cic_process.kill()
                self.cic_process.wait()
            logger.info("CICFlowMeter process terminated.")

    def _run_cicflowmeter_live(self):
        logger.info(
            f"Starting CICFlowMeter on interface {self.config.system.interface}..."
        )

        csv_path = Path(self.config.system.csv_output_path)

        # Ensure log directory exists
        if csv_path.parent:
            csv_path.parent.mkdir(parents=True, exist_ok=True)

        # Check & Delete old file
        if csv_path.exists():
            try:
                csv_path.unlink()
                logger.info(f"Removed existing CSV log: {csv_path}")
            except OSError as e:
                logger.warning(f"Could not remove old CSV log: {e}")

        cmd = [
            "cicflowmeter",
            "-i",
            self.config.system.interface,
            "-c",
            str(csv_path),
        ]

        # Run in background, suppress standard output to keep CLI clean
        self.cic_process = subprocess.Popen(cmd, stdout=None, stderr=None)  # nosec B603
        self._read_csv_live(csv_path)

    def _read_csv_live(self, csv_path: Path):
        logger.info(f"Capturing flows in {csv_path}... CRTL+C to stop.")

        # Wait for file creation
        while not csv_path.exists():
            time.sleep(1)
            if not self.running:
                return

        def follow(thefile):
            while True:
                line = thefile.readline()
                if not line:
                    if not self.running:
                        break
                    time.sleep(0.5)
                    continue
                yield line

        with open(csv_path, "r") as f:
            features: list[str] = []
            logger.info("Waiting for CSV header features...")

            while not features:
                line = f.readline()
                if line.strip():
                    features = line.strip().split(",")
                    logger.info("Header detected")
                else:
                    time.sleep(0.5)

            for line in follow(f):
                if not line.strip():
                    continue

                try:
                    record = line.strip().split(",")
                    if len(record) == len(features):
                        data_dict = dict(zip(features, record))
                        # logger.info(data_dict)
                        self.raw_packet_queue.put(data_dict)
                except Exception as e:
                    logger.exception("Error processing line")
                    logger.debug(f"Exception: {e}")

    def _run_cicflowmeter_pcap(self, pcap_path: Optional[Path]):
        logger.info(f"Processing PCAP file: {pcap_path}")
        output_dir = Path(self.config.system.test_mode_output_path).parent
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            "cicflowmeter",
            "-f",
            str(pcap_path),
            "-c",
            str(self.config.system.test_mode_output_path),
        ]
        try:
            subprocess.run(cmd, check=True)  # nosec B603
            logger.info("PCAP conversion complete.")
            self._read_csv_direct(Path(self.config.system.test_mode_output_path))
        except subprocess.CalledProcessError as e:
            logger.error(f"CICFlowMeter in PCAP failed: {e}")

    def _read_csv_direct(self, csv_path: Optional[Path]):
        if not csv_path or not csv_path.exists():
            logger.error(f"CSV file not found at {csv_path}")
            return

        logger.info(f"Loading CSV from {csv_path}")

        try:
            chunk_size = 5000
            for chunk in pd.read_csv(csv_path, chunksize=chunk_size):
                if not self.running:
                    break

                records = chunk.to_dict(orient="records")

                for record in records:
                    if not self.running:
                        break
                    self.raw_packet_queue.put(record)

            logger.info(f"Finished reading CSV: {csv_path}")
        except Exception as e:
            logger.error(f"Error reading CSV direct: {e}")
