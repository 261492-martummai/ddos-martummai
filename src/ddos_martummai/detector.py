import logging
import sys
import time
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
        self.ip_memory = dict[str, dict[str, float]]()

    def start(self):
        logger.info("Detector Started")
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
        """
        DDoS Detection Strategy (4 Cases)

        Case 1: Small attackers, high frequency
            - Few IPs generate many malicious flows.
            - Detected by per-IP volume and ML ratio.

        Case 2: Small attackers, low frequency
            - Normal users or harmless traffic.
            - Intentionally ignored.

        Case 3: Large attackers, low frequency (slow botnet)
            - Many IPs send low-rate but consistently malicious traffic.
            - Detected using temporal memory.

        Case 4: Large attackers, high frequency (global botnet)
            - Massive distributed flood.
            - Detected using global batch statistics.
        """

        if batch_df.empty:
            return

        try:
            now = time.time()
            src_ips = batch_df[IP_COLUMN_NAME].reset_index(drop=True)
            features = batch_df.drop(columns=[IP_COLUMN_NAME])

            # ML prediction
            predictions = self.model.predict(features)
            results = pd.DataFrame({"ip": src_ips, "is_attack": predictions})

            total_flows = len(results)
            unique_ips = results["ip"].nunique()
            global_attack_ratio = results["is_attack"].mean()

            logger.info(
                f"[BATCH] flows={total_flows} "
                f"unique_ips={unique_ips} "
                f"attack_ratio={global_attack_ratio:.2f}"
            )

            # ===============================
            # CASE 4: Big distributed botnet
            # ===============================
            if global_attack_ratio > 0.7 and unique_ips > total_flows * 0.3:
                logger.critical("[GLOBAL BOTNET] Distributed DDoS detected")

                ip_stats = results.groupby("ip")["is_attack"].agg(["count", "mean"])
                top_ips = ip_stats.sort_values("count", ascending=False).head(10)

                for ip, row in top_ips.iterrows():
                    logger.warning(f"[BOTNET BLOCK] {ip}")
                    self.mitigator.block_ip(str(ip))
                return

            # ===============================
            # Update temporal memory (Case 3)
            # ===============================
            for ip, is_attack in zip(results["ip"], results["is_attack"]):
                if ip not in self.ip_memory:
                    self.ip_memory[ip] = {
                        "total": 0,
                        "attack": 0,
                        "first": now,
                        "last": now,
                    }
                self.ip_memory[ip]["total"] += 1
                self.ip_memory[ip]["attack"] += int(is_attack)
                self.ip_memory[ip]["last"] = now

            # ===============================
            # CASE 3: Slow distributed attackers
            # ===============================
            SLOW_ATTACKERS = []

            for ip, stats in self.ip_memory.items():
                duration = stats["last"] - stats["first"]
                if duration < 300:  # must persist at least 5 minutes
                    continue

                ratio = stats["attack"] / stats["total"]

                if ratio > 0.4 and stats["total"] > 30:
                    SLOW_ATTACKERS.append((ip, stats, ratio))

            for ip, stats, ratio in SLOW_ATTACKERS:
                logger.warning(
                    f"[SLOW ATTACK] {ip} "
                    f"total={stats['total']} "
                    f"ratio={ratio:.2f} "
                    f"duration={int(stats['last'] - stats['first'])}s"
                )
                self.mitigator.block_ip(ip)

            # ===============================
            # CASE 1 & 2: Normal IP detection
            # ===============================
            ip_stats = results.groupby("ip")["is_attack"].agg(["count", "mean"])

            MIN_FLOWS = max(10, int(total_flows * 0.02))
            IP_THRESHOLD = 0.6

            attackers = ip_stats[
                (ip_stats["mean"] > IP_THRESHOLD) & (ip_stats["count"] >= MIN_FLOWS)
            ]

            for ip, row in attackers.iterrows():
                logger.warning(
                    f"[IP ATTACK] {ip} count={row['count']} ratio={row['mean']:.2f}"
                )
                self.mitigator.block_ip(str(ip))

            logger.info(
                f"[SUMMARY] attackers={len(attackers)} slow_attackers={len(SLOW_ATTACKERS)}"
            )

        except Exception as e:
            logger.exception(f"Batch prediction error: {e}")
