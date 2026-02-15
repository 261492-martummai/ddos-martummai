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
        logger.info("Detector Start")
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

            predictions = self.model.predict(features)
            results = pd.DataFrame({"ip": src_ips, "is_attack": predictions})

            total_flows = len(results)

            # IP-level stats
            ip_stats = results.groupby("ip")["is_attack"].agg(["count", "mean"])
            ip_stats["ratio"] = ip_stats["count"] / total_flows

            # Subnet-level stats (/24)
            results["subnet"] = results["ip"].apply(
                lambda x: ".".join(x.split(".")[:3])
            )
            subnet_stats = results.groupby("subnet")["is_attack"].agg(["count", "mean"])
            subnet_stats["ratio"] = subnet_stats["count"] / total_flows

            logger.info(
                f"\n--- BATCH ({total_flows}) ---\n"
                + ip_stats.to_string()
                + "\n--- SUBNET SUMMARY ---\n"
                + subnet_stats.to_string()
            )

            # ---------- Thresholds (percentage-based) ----------
            ATTACK_MEAN = 0.6          # model confidence
            IP_RATIO = 0.2             # 20% of batch
            SUBNET_RATIO = 0.3         # 30% of batch

            # ---------- Case 1: Small attacker, high frequency ----------
            ip_attackers = ip_stats[
                (ip_stats["ratio"] > IP_RATIO) &
                (ip_stats["mean"] > ATTACK_MEAN)
            ]

            # ---------- Case 2: Big attackers, high frequency ----------
            subnet_attackers = subnet_stats[
                (subnet_stats["ratio"] > SUBNET_RATIO) &
                (subnet_stats["mean"] > ATTACK_MEAN)
            ]

            # Mitigation
            for ip in ip_attackers.index:
                logger.warning(f"[IP BLOCK] DDoS from {ip}")
                self.mitigator.block_ip(ip)

            for subnet in subnet_attackers.index:
                logger.warning(f"[SUBNET BLOCK] DDoS from {subnet}.0/24")
                self.mitigator.block_subnet(subnet)

        except Exception as e:
            logger.exception(f"Batch prediction error: {e}")
