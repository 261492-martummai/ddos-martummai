from __future__ import annotations

import logging
import sys
import time
import warnings
from multiprocessing import Queue
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from ddos_martummai.init_models import AppConfig
from ddos_martummai.mitigator import Mitigator
from ddos_martummai.util.constant import IP_COLUMN_NAME
from ddos_martummai.web.drift_monitor import update_meta_prob

warnings.filterwarnings(
    "ignore", message=".*sklearn.utils.parallel.delayed.*", category=UserWarning
)

logger = logging.getLogger("DETECTOR")


class DDoSDetector:
    def __init__(
        self,
        model_path: Path,
        config: AppConfig,
        cleaned_packet_queue: Queue[pd.DataFrame | None],
    ):
        self.config = config.detector
        self.model = self._load_model(model_path)
        self.mitigator = Mitigator(config)
        self.cleaned_packet_queue = cleaned_packet_queue
        self.batch_size = config.model.batch_size
        self.ip_memory: dict[str, dict[str, float]] = {}
        self.last_cleanup_time = time.time()

    def start(self):
        logger.info("Detector Started")
        while True:
            batch = self.cleaned_packet_queue.get()

            if batch is None:
                logger.info("Detector Stopped.")
                break

            self._predict_batch(batch)

    def _load_model(self, model_path: Path):
        logger.debug(f"Loading Internal Model from: {model_path}")

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
            src_ips = batch_df[IP_COLUMN_NAME].values
            features = batch_df.drop(columns=[IP_COLUMN_NAME])

            # Calculate model confidence and update temporal memory
            probs = self.model.predict_proba(features)
            avg_confidence = float(np.mean(np.max(probs, axis=1)))
            update_meta_prob(avg_confidence)

            # ML prediction
            predictions = self.model.predict(features)
            results = pd.DataFrame({"ip": src_ips, "is_attack": predictions})

            total_flows = len(results)
            global_attack_ratio = results["is_attack"].mean()
            unique_ips = results["ip"].unique()
            ip_diversity = len(unique_ips) / total_flows if total_flows > 0 else 0

            logger.info(
                f"[BATCH] flows={total_flows} unique_ips={len(unique_ips)} attack_ratio={global_attack_ratio:.2f}"
            )

            # ==========================================
            # CASE 4: Global Botnet
            # ==========================================
            if (
                total_flows >= self.config.global_min_samples
                and global_attack_ratio > self.config.global_attack_ratio
                and ip_diversity > self.config.global_ip_diversity
            ):
                logger.critical(
                    f"[GLOBAL ATTACK] Detected: Ratio={global_attack_ratio:.2f}, Divers={ip_diversity:.2f}"
                )
                self._mitigate_top_offenders(
                    results, global_attack_ratio, ip_diversity, limit=10
                )
                return

            # ==========================================
            # Temporal Memory & CASE 3 (Slow Botnet)
            # ==========================================
            current_batch_stats = results.groupby("ip")["is_attack"].agg(
                ["count", "sum", "mean"]
            )

            for raw_ip, row in current_batch_stats.iterrows():
                ip = str(raw_ip)

                if ip not in self.ip_memory:
                    self.ip_memory[ip] = {
                        "total": 0,
                        "attack": 0,
                        "first": now,
                        "last": now,
                    }

                m = self.ip_memory[ip]
                m["total"] += row["count"]
                m["attack"] += row["sum"]
                m["last"] = now

                # Flow Rate (PPS) Analysis
                duration = m["last"] - m["first"]
                if duration >= self.config.slow_min_duration:
                    pps = m["total"] / duration
                    attack_ratio = m["attack"] / m["total"]

                    # If an IP has a high attack ratio but low PPS, it may indicate a slow/persistent attack.
                    if (
                        attack_ratio > self.config.slow_attack_ratio
                        and pps > self.config.slow_max_pps
                    ):
                        log = f"[SLOW ATTACK] {ip} | PPS: {pps:.2f}, Ratio: {attack_ratio:.2f}"
                        logger.warning(log)

                        self.mitigator.block_ip(ip)
                        self.mitigator.send_alert(ip, log)

                        del self.ip_memory[ip]
                        continue

            # ==========================================
            # CASE 1: Burst Attack (Per-Batch Detection)
            # ==========================================
            if (
                row["mean"] > self.config.ip_burst_threshold
                and row["count"] >= self.config.ip_min_count_in_batch
            ):
                log = f"[BURST ATTACK] {ip} | Count: {row['count']}, Ratio: {row['mean']:.2f}"
                logger.warning(log)

                self.mitigator.block_ip(ip)
                self.mitigator.send_alert(ip, log)

                if ip in self.ip_memory:
                    del self.ip_memory[ip]

            # ==========================================
            # Periodic Memory Cleanup
            # ==========================================
            if now - self.last_cleanup_time > self.config.cleanup_interval:
                self._cleanup_memory(now)
                self.last_cleanup_time = now

        except Exception as e:
            logger.exception(f"Batch prediction error: {e}")

    def _mitigate_top_offenders(
        self, results, global_attack_ratio, ip_diversity, limit
    ):
        """Helper to block top heavy-hitters during global flood"""
        top_ips = results.groupby("ip").size().sort_values(ascending=False).head(limit)
        ips_to_block = top_ips.index.astype(str).tolist()

        for ip in ips_to_block:
            self.mitigator.block_ip(ip)

        text = f"Global Botnet Attack - Top Offenders Blocked with Attack Ratio: {global_attack_ratio:.2f} and IP Diversity: {ip_diversity:.2f}"
        self.mitigator.send_alert(ips_to_block, text)

    def _cleanup_memory(self, now):
        """Prevent Memory Leaks by removing stale IPs"""
        cutoff = now - self.config.mem_timeout
        initial_size = len(self.ip_memory)
        self.ip_memory = {k: v for k, v in self.ip_memory.items() if v["last"] > cutoff}
        logger.info(
            f"[MEM] Cleanup done. Size: {initial_size} -> {len(self.ip_memory)}"
        )
