import logging
import os
import subprocess  # nosec B404
import sys
import time
from pathlib import Path
from queue import Queue
from typing import Optional

import pandas as pd

from ddos_martummai.init_models import AppConfig

logger = logging.getLogger("READER")


class Reader:
    def __init__(self, config: AppConfig, mode: str = "live"):
        self.config = config
        self.mode = mode
        self.running = False
        self.cic_process: Optional[subprocess.Popen] = None
        self.raw_packet_queue: Queue[dict | None] = Queue()

    def get_queue(self) -> Queue[dict | None]:
        return self.raw_packet_queue

    # ---------- Public API ----------

    def start(self, input_file: Optional[Path] = None):
        logger.info("Reader started")
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
            self._shutdown()

    def stop(self):
        logger.info("Stopping Reader...")
        self.running = False
        self._terminate_cic()

    # ---------- Mode Handlers ----------

    def _run_live(self):
        csv_path = Path(self.config.system.csv_output_path)
        self._prepare_csv(csv_path)
        self._start_cicflowmeter_live(csv_path)
        self._stream_csv(csv_path)

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

    def _start_cicflowmeter_live(self, csv_path: Path):
        cmd = self._build_cic_cmd(
            "-i", self.config.system.interface, csv_path
        )
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

    def _prepare_csv(self, csv_path: Path):
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        if csv_path.exists():
            csv_path.unlink()
            logger.info(f"Removed old CSV: {csv_path}")

    def _stream_csv(self, csv_path: Path):
        logger.info(f"Waiting for CSV: {csv_path}")

        while not csv_path.exists() and self.running:
            time.sleep(0.5)

        with open(csv_path, "r") as f:
            headers = self._wait_for_header(f)
            for line in self._follow_file(f):
                if not line.strip():
                    continue

                record = line.strip().split(",")
                if len(record) == len(headers):
                    self.raw_packet_queue.put(dict(zip(headers, record)))

    def _wait_for_header(self, file):
        logger.info("Waiting for CSV headers...")
        while self.running:
            line = file.readline()
            if line.strip():
                logger.info("Headers detected")
                return line.strip().split(",")
            time.sleep(0.3)

    def _follow_file(self, file):
        while self.running:
            line = file.readline()
            if line:
                yield line
            else:
                time.sleep(0.3)

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

    # ---------- Shutdown ----------

    def _shutdown(self):
        self.stop()
        self.raw_packet_queue.put(None)
        logger.info("Reader stopped")