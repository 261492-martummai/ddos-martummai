import logging
import os
import subprocess  # nosec B404
import sys
import time
from pathlib import Path
from queue import Queue
import joblib
import pandas as pd

from .config_loader import AppConfig
from .mitigation import Mitigator

logger = logging.getLogger("ddos-martummai")


class DDoSDetector:
    
    def __init__(self, model_path: Path, config: AppConfig, cleaned_packet_queue: Queue):
        self.config = config
        self.model = self._load_model(model_path)
        self.mitigator = Mitigator(config)
        self.cleaned_packet_queue = cleaned_packet_queue
        self.running = False
        self.cic_process = None

    def start(self):
        print("Detector: Start")
        while True:
            item = self.cleaned_packet_queue.get()
            if item is None:
                print("Detector: Received None -> Exiting")
                break
        self._process_queue()                     

            
    def _load_model(self, model_path: Path):
        # current_dir = Path(__file__).parent.resolve()
        # model_dir = current_dir / "models"
        # self.model_path = model_dir / "model.joblib"

        # logger.info("Initializing DDoS Guard...")
        logger.info(f"Loading Internal Model from: {model_path}")

        if not model_path.exists():
            logger.error(f"[FATAL] Model file not found at {model_path}")
            logger.error(
                "The package was built without model files or they are missing."
            )
            sys.exit(1)

        try:
            self.model = joblib.load(model_path)
            logger.info("Model loaded successfully.")
        except Exception as e:
            logger.error(f"Error loading model/scaler: {e}")
            sys.exit(1)

    def _process_queue(self):
        batch = []
        while True:
            if not self.cleaned_packet_queue.empty():
                pkt = self.cleaned_packet_queue.get()
                if pkt is None:
                    print("Detector: Received None -> Exiting")
                    break
                
                batch.append(pkt)
                if len(batch) >= self.batch_size:
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
            data = {
                "Color": ["Red", "Blue", "Green", "Red", "Blue"],
                "Amount": [10, 20, 15, 25, 30],
            }
            df = pd.DataFrame(data)
            X = pd.get_dummies(df["Color"], prefix="Color")
            # Convert to numeric, handle errors
            X = X.apply(pd.to_numeric, errors="coerce").fillna(0)

            # Scale
            X_scaled = self.scaler.transform(X)

            # Predict
            predictions = self.model.predict(X_scaled)

            # TODO: maybe switch to % alert
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
