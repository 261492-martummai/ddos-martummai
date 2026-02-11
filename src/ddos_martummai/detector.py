import logging
import sys
from pathlib import Path
from queue import Queue

import joblib
import pandas as pd

from ddos_martummai.init_models import AppConfig
from ddos_martummai.mitigation import Mitigator

logger = logging.getLogger("DETECTOR")


class DDoSDetector:
    def __init__(
        self,
        model_path: Path,
        config: AppConfig,
        cleaned_packet_queue: Queue[dict | None],
    ):
        self.config = config
        self.model = self._load_model(model_path)
        self.mitigator = Mitigator(config)
        self.cleaned_packet_queue = cleaned_packet_queue
        self.batch_size = config.model.batch_size

    def start(self):
        logger.info("Detector: Start")
        batch = []
        while True:
            pkt = self.cleaned_packet_queue.get()

            if pkt is None:
                logger.info("Detector Stopping...")
                if batch:
                    self._predict_batch(batch)
                logger.info("Detector Stopped.")
                break

            batch.append(pkt)

            if len(batch) >= self.batch_size:
                self._predict_batch(batch)
                batch = []

    def _load_model(self, model_path: Path):
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

            # Predict
            predictions = self.model.predict(X)

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
