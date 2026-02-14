import logging
import sys
from pathlib import Path
from queue import Queue
from ipaddress import ip_network


import joblib
import pandas as pd

from ddos_martummai.init_models import AppConfig
from ddos_martummai.mitigation import Mitigator

logger = logging.getLogger("DETECTOR")

IP_COLUMN_NAME = "src_ip"

def _get_subnet(ip: str, mask=24):
	return str(ip_network(f"{ip}/{mask}", strict=False).network_address)


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

                    # ---------- CASE 4: Big botnet ----------
                    if global_attack_ratio > 0.7 and unique_ips > total_flows * 0.3:
                            logger.critical("[GLOBAL BOTNET] Distributed DDoS detected")

                            # Block top 10 most aggressive IPs
                            top_ips = (
                                    results.groupby("ip")["is_attack"]
                                    .agg(["count", "mean"])
                                    .sort_values("count", ascending=False)
                                    .head(10)
                            )

                            for ip, row in top_ips.iterrows():
                                    logger.warning(f"[BOTNET BLOCK] {ip} count={row['count']}")
                                    self.mitigator.block_ip(ip)
                                    # self.mitigator.send_alert(ip, row.to_string())
                            return

                    # ---------- Normal IP-level detection ----------
                    ip_stats = results.groupby("ip")["is_attack"].agg(["count", "mean"])

                    # dynamic thresholds
                    MIN_FLOWS = max(5, int(total_flows * 0.01))
                    IP_THRESHOLD = 0.5

                    attackers = ip_stats[
                            (ip_stats["mean"] > IP_THRESHOLD)
                            & (ip_stats["count"] >= MIN_FLOWS)
                    ]

                    for ip, row in attackers.iterrows():
                            logger.warning(
                                    f"[IP ATTACK] {ip} "
                                    f"count={row['count']} "
                                    f"ratio={row['mean']:.2f}"
                            )
                            self.mitigator.block_ip(ip)
                            # self.mitigator.send_alert(ip, row.to_string())

                    logger.info(
                            f"[SUMMARY] attackers={len(attackers)}"
                    )

            except Exception as e:
                    logger.exception(f"Batch prediction error: {e}")



    # def _predict_batch(self, batch_df: pd.DataFrame):
    #     if batch_df.empty:
    #         return

    #     try:
    #         src_ips = batch_df[IP_COLUMN_NAME].reset_index(drop=True)
    #         features = batch_df.drop(columns=[IP_COLUMN_NAME])

    #         # Predict
    #         predictions = self.model.predict(features)
    #         results = pd.DataFrame({"ip": src_ips, "is_attack": predictions})
    #         total_flows = len(results)


    #         # TODO: maybe switch to % alert
    #         ip_stats = results.groupby("ip")["is_attack"].agg(["count", "mean"])
    #         ip_stats["ratio"] = ip_stats["count"] / total_flows


    #         logger.info(
    #             f"\n--- BATCH PREDICTIONS ({len(results)} rows) ---\n"
    #             + results.to_string(index=False)
    #             + "\n--- IP STATISTICS SUMMARY ---\n"
    #             + ip_stats.to_string()
    #         )
    #         # ตั้งค่า Threshold (ควรดึงจาก Config)
    #         # เช่น 0.5 หมายถึง ถ้าเกิน 50% ของ traffic จาก IP นี้เป็น Attack -> Block
    #         ATTACK_THRESHOLD = 0.5
    #         MIN_PACKETS = 2  # กันเหนียว: ต้องส่งมาอย่างน้อย 2 packet ถึงจะตัดสิน (ลด noise)

    #         # # Filter เอาเฉพาะคนที่เป็น Hacker (Mean > Threshold)
    #         attackers = ip_stats[
    #             (ip_stats["mean"] > ATTACK_THRESHOLD)
    #             & (ip_stats["count"] >= MIN_PACKETS)
    #         ]
    #         for ip, row in attackers.iterrows():
    #             logger.warning(f"[DETECTED] DDoS from {ip}")
    #             # self.mitigator.send_alert(str(ip), row.to_string())
    #             self.mitigator.block_ip(ip)

    #         # # 5. Mitigation Action

    #     except Exception as e:
    #         logger.exception(f"Batch prediction error: {e}")
