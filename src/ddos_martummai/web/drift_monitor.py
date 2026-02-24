import json
import logging
import time
from collections import deque
from pathlib import Path

import numpy as np

logger = logging.getLogger("ML_MONITOR")

current_dir = Path(__file__).parent.resolve()
baseline_file = current_dir / "baseline.json"

WINDOW = 60
meta_prob_history: deque = deque(maxlen=WINDOW)
pkt_rate_history: deque = deque(maxlen=WINDOW)
byte_rate_history: deque = deque(maxlen=WINDOW)

AUTO_BASELINE_THRESHOLD_MIN = 0.1
AUTO_BASELINE_THRESHOLD_MAX = 0.45
AUTO_BASELINE_DURATION = 3600

drift_stable_start_time = None

def update_meta_prob(prob: float):
    meta_prob_history.append(prob)


def update_drift_rate(pkt_rate: int, byte_rate: int):
    pkt_rate_history.append(pkt_rate)
    byte_rate_history.append(byte_rate)


# ---------- baseline ----------
def save_baseline():
    pkt_mean = float(np.mean(pkt_rate_history))
    byte_mean = float(np.mean(byte_rate_history))

    data = {"pkt_mean": pkt_mean, "byte_mean": byte_mean, "timestamp": time.time()}
    baseline_file.write_text(json.dumps(data, indent=2))

    logger.info(
        f"[ACTION] New Baseline Saved: Packets={pkt_mean:.2f}/s, Bandwidth={byte_mean:.2f} B/s"
    )


def load_baseline():
    if not baseline_file.exists():
        return None
    return json.loads(baseline_file.read_text())


def check_auto_baseline(current_drift: float):
    global drift_stable_start_time

    if AUTO_BASELINE_THRESHOLD_MIN <= current_drift <= AUTO_BASELINE_THRESHOLD_MAX:
        if drift_stable_start_time is None:
            drift_stable_start_time = time.time()
            logger.info("[AUTO-BASELINE] Drift stable in range. Timer started.")
        else:
            elapsed = time.time() - drift_stable_start_time
            if elapsed >= AUTO_BASELINE_DURATION:
                logger.info(
                    f"[AUTO-BASELINE] Drift stable for {AUTO_BASELINE_DURATION}s. Updating baseline..."
                )
                save_baseline()
                drift_stable_start_time = None
    else:
        if drift_stable_start_time is not None:
            logger.debug("[AUTO-BASELINE] Drift exited stable range. Timer reset.")
            drift_stable_start_time = None


# ---------- PSI (simple drift score) ----------
def drift_score():
    base = load_baseline()
    if not base or len(pkt_rate_history) < 10:
        return 0.0

    cur_mean_pkt = np.mean(pkt_rate_history)
    cur_mean_byte = np.mean(byte_rate_history)

    # calculate percentage shift from baseline
    pkt_shift = abs(cur_mean_pkt - base["pkt_mean"]) / (base["pkt_mean"] + 1)
    byte_shift = abs(cur_mean_byte - base["byte_mean"]) / (base["byte_mean"] + 1)

    # Model Confidence Drift
    conf_shift = 0
    if len(meta_prob_history) > 0:
        avg_conf = np.mean(meta_prob_history)
        conf_shift = max(0, 0.9 - avg_conf)

    total_drift = ((pkt_shift + byte_shift) / 2) * 0.6 + (conf_shift * 0.4)

    return float(min(total_drift, 1.0))
