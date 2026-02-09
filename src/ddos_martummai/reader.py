import logging
import os
import subprocess  # nosec B404
# import sys
import time
# from pathlib import Path
# from queue import Queue
from threading import Thread

import pandas as pd

from .config_loader import AppConfig
from .mitigation import Mitigator

logger = logging.getLogger("ddos-martummai")

class Reader:
    def __init__(self, config: AppConfig):
        self.config = config    
        self.mitigator = Mitigator(config.mitigation)
        self.running = False
        self.cic_process = None
    
    def start_monitoring(self, mode: str, input_file: str):
        self.running = True

        # Start Consumer Thread (Predictor)
        processor_thread = Thread(target=self._process_queue, daemon=True)
        processor_thread.start()

        try:
            if mode == "live":
                self._run_cicflowmeter_live()
            elif mode == "pcap":
                self._run_cicflowmeter_pcap(input_file)
            elif mode == "csv":
                self._read_csv_direct(input_file)

            # Keep main thread alive
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        logger.info("Stopping DDoS Guard Service...")
        self.running = False
        if self.cic_process:
            self.cic_process.terminate()

    def _run_cicflowmeter_live(self):
        logger.info(
            f"Starting CICFlowMeter on interface {self.config.system.interface}..."
        )

        # Ensure log directory exists
        log_dir = os.path.dirname(self.config.system.csv_output_path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        cmd = [
            "cicflowmeter",
            "-i",
            self.config.system.interface,
            "-c",
            self.config.system.csv_output_path,
        ]

        # Run in background, suppress standard output to keep CLI clean
        self.cic_process = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )  # nosec B603
        self._read_csv_live(self.config.system.csv_output_path)

    def _run_cicflowmeter_pcap(self, pcap_path: str):
        logger.info(f"Processing PCAP file: {pcap_path}")
        output_dir = os.path.dirname(self.config.system.test_mode_output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        cmd = [
            "cicflowmeter",
            "-f",
            pcap_path,
            "-c",
            self.config.system.test_mode_output_path,
        ]

        subprocess.run(cmd, check=True)  # nosec B603
        self._read_csv_direct(self.config.system.test_mode_output_path)

    def _read_csv_live(self, csv_path: str):
        logger.info(f"Waiting for flows in {csv_path}...")

        # Wait for file creation
        while not os.path.exists(csv_path):
            time.sleep(1)
            if not self.running:
                return

        with open(csv_path, "r") as f:
            features = f.readline().strip().split(",")
            # Go to end of file to read only new flows
            f.seek(0, 2)  # TODO: what is this

            while self.running:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue

                try:
                    record = line.strip().split(",")
                    if len(record) == len(features):
                        data_dict = dict(zip(features, record))
                        self.packet_queue.put(data_dict)
                except Exception:
                    logger.exception("Error reading flow line.")

    def _read_csv_direct(self, csv_path: str):
        if not os.path.exists(csv_path):
            logger.error(f"CSV file not found at {csv_path}")
            return

        df = pd.read_csv(csv_path)
        logger.info(f"Loaded {len(df)} flows. Processing...")

        for _, row in df.iterrows():
            if not self.running:
                break
            self.packet_queue.put(row.to_dict())

    def _read_csv_live(self, csv_path: str):
        logger.info(f"Waiting for flows in {csv_path}...")

        # Wait for file creation
        while not os.path.exists(csv_path):
            time.sleep(1)
            if not self.running:
                return

        with open(csv_path, "r") as f:
            features = f.readline().strip().split(",")
            # Go to end of file to read only new flows
            f.seek(0, 2)  # TODO: what is this

            while self.running:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue

                try:
                    record = line.strip().split(",")
                    if len(record) == len(features):
                        data_dict = dict(zip(features, record))
                        self.packet_queue.put(data_dict)
                except Exception:
                    logger.exception("Error reading flow line.")

    def _read_csv_direct(self, csv_path: str):
        if not os.path.exists(csv_path):
            logger.error(f"CSV file not found at {csv_path}")
            return

        df = pd.read_csv(csv_path)
        logger.info(f"Loaded {len(df)} flows. Processing...")

        for _, row in df.iterrows():
            if not self.running:
                break
            self.packet_queue.put(row.to_dict())