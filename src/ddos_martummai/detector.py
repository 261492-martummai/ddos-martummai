import logging
import sys
from pathlib import Path
from queue import Queue

import joblib
import pandas as pd

from ddos_martummai.init_models import AppConfig
from ddos_martummai.mitigation import Mitigator

logger = logging.getLogger("DETECTOR")

IP_COLUMN_NAME = "src_ip"


class DDoSDetector:
    def __init__(
        self,
        model_path: Path,
        config: AppConfig,
        cleaned_packet_queue: Queue[pd.DataFrame | None],
    ):
        self.config = config
        self.model = self._load_model(model_path)
        self.mitigator = Mitigator(config)
        self.cleaned_packet_queue = cleaned_packet_queue
        self.batch_size = config.model.batch_size

    def start(self):
        logger.info("Detector: Start")
        while True:
            batch = self.cleaned_packet_queue.get()

            if batch is None:
                logger.info("Detector Stopped.")
                break

            self._predict_batch(batch)

    def _load_model(self, model_path: Path):
        logger.info(f"Loading Internal Model from: {model_path}")

        if not model_path.exists():
            logger.error(f"[FATAL] Model file not found at {model_path}")
            logger.error(
                "The package was built without model files or they are missing."
            )
            sys.exit(1)

        try:
            return joblib.load(model_path)
        except Exception as e:
            logger.error(f"Error loading model/scaler: {e}")
            sys.exit(1)
        finally:
            logger.info("Model loaded successfully.")

    def _predict_batch(self, batch_df: pd.DataFrame):
        if batch_df.empty:
            return

        try:
            src_ips = batch_df[IP_COLUMN_NAME].reset_index(drop=True)
            features = batch_df.drop(columns=[IP_COLUMN_NAME])

            # Predict
            predictions = self.model.predict(features)
            results = pd.DataFrame({"ip": src_ips, "is_attack": predictions})

            # TODO: maybe switch to % alert
            ip_stats = results.groupby("ip")["is_attack"].agg(["count", "mean"])

            logger.info(
                f"\n--- BATCH PREDICTIONS ({len(results)} rows) ---\n"
                + results.to_string(index=False)
                + "\n--- IP STATISTICS SUMMARY ---\n"
                + ip_stats.to_string()
            )
            # # ตั้งค่า Threshold (ควรดึงจาก Config)
            # # เช่น 0.5 หมายถึง ถ้าเกิน 50% ของ traffic จาก IP นี้เป็น Attack -> Block
            ATTACK_THRESHOLD = 0.5
            MIN_PACKETS = 2  # กันเหนียว: ต้องส่งมาอย่างน้อย 2 packet ถึงจะตัดสิน (ลด noise)

            # # Filter เอาเฉพาะคนที่เป็น Hacker (Mean > Threshold)
            attackers = ip_stats[
                (ip_stats["mean"] > ATTACK_THRESHOLD)
                & (ip_stats["count"] >= MIN_PACKETS)
            ]
            for ip, row in attackers.iterrows():
                logger.warning(f"[DETECTED] DDoS from {ip}")
                self.mitigator.send_alert(str(ip), row.to_string())
                # self.mitigator.block_ip(ip)

            # # 5. Mitigation Action

        except Exception as e:
            logger.exception(f"Batch prediction error: {e}")
