import logging
import os
import subprocess  # nosec B404
import sys
import time
from pathlib import Path
from queue import Queue
from threading import Thread

import joblib
import pandas as pd

from .config_loader import AppConfig
from .mitigation import Mitigator

logger = logging.getLogger("ddos-martummai")


class DDoSDetector:
    def __init__(self, config: AppConfig):
        self.config = config

        current_dir = Path(__file__).parent.resolve()
        model_dir = current_dir / "models"
        self.model_path = model_dir / "model.joblib"
        self.scaler_path = model_dir / "scaler.joblib"

        logger.info("Initializing DDoS Guard...")
        logger.info(f"Loading Internal Model from: {self.model_path}")

        if not self.model_path.exists():
            logger.error(f"[FATAL] Model file not found at {self.model_path}")
            logger.error(
                "The package was built without model files or they are missing."
            )
            sys.exit(1)

        try:
            self.model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
            logger.info("Model and Scaler loaded successfully.")
        except Exception as e:
            logger.error(f"Error loading model/scaler: {e}")
            sys.exit(1)

        self.mitigator = Mitigator(config.mitigation)
        self.packet_queue = Queue()
        self.running = False
        self.cic_process = None

    def start_monitoring(self, mode: str, input_file: str = None):
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
        self._tail_csv(self.config.system.csv_output_path)

    def _run_cicflowmeter_pcap(self, pcap_path: str):
        logger.info(f"Processing PCAP file: {pcap_path}")
        output_dir = os.path.dirname(self.config.system.test_mode_output)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        cmd = [
            "cicflowmeter",
            "-f",
            pcap_path,
            "-c",
            self.config.system.test_mode_output,
        ]

        subprocess.run(cmd, check=True)  # nosec B603
        self._read_csv_direct(self.config.system.test_mode_output)

    def _tail_csv(self, csv_path: str):
        logger.info(f"Waiting for flows in {csv_path}...")

        # Wait for file creation
        while not os.path.exists(csv_path):
            time.sleep(1)
            if not self.running:
                return

        with open(csv_path, "r") as f:
            headers = f.readline().strip().split(",")
            # Go to end of file to read only new flows
            f.seek(0, 2)

            while self.running:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue

                try:
                    row = line.strip().split(",")
                    if len(row) == len(headers):
                        data_dict = dict(zip(headers, row))
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

    def _process_queue(self):
        batch = []
        while self.running:
            if not self.packet_queue.empty():
                batch.append(self.packet_queue.get())

                if len(batch) >= self.config.model.batch_size:
                    self._predict_batch(batch)
                    batch = []
            else:
                if batch:
                    self._predict_batch(batch)
                    batch = []
                time.sleep(0.1)

    def _predict_batch(self, batch_data: list):
        # Dummy Code
        if not batch_data:
            return
        df = pd.DataFrame(batch_data)

        try:
            # Select only required features
            X = df[self.config.model.features]
            # Convert to numeric, handle errors
            X = X.apply(pd.to_numeric, errors="coerce").fillna(0)

            # Scale
            X_scaled = self.scaler.transform(X)

            # Predict
            predictions = self.model.predict(X_scaled)

            for i, pred in enumerate(predictions):
                if pred == 1:  # Attack Detected
                    # Try to find IP column with various possible names
                    src_ip = None
                    for col in ["src_ip", "Src IP", "Source IP"]:
                        if col in df.columns:
                            src_ip = df.iloc[i][col]
                            break

                    if src_ip:
                        logger.warning(f"[DETECTED] DDoS Flow from {src_ip}")
                        self.mitigator.send_alert(src_ip, str(df.iloc[i].to_dict()))
                        if self.config.mitigation.enable_blocking:
                            self.mitigator.block_ip(src_ip)

        except Exception as e:
            logger.exception(f"Batch prediction error: {e}")
