import logging
from pathlib import Path
from queue import Empty, Queue
from typing import Dict, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from ddos_martummai.util.constant import COLUMN_RENAME_MAP

logger = logging.getLogger("PREPROCESSOR")


# ============================================================================
# PURE FUNCTIONS
# ============================================================================
def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Strip whitespace from column names."""
    df_clean = df.copy()
    df_clean.columns = df_clean.columns.str.strip()

    return df_clean


def select_numeric_columns(
    df: pd.DataFrame, feature_cols: list
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Split src_ip and feature columns from dataframe."""
    src_ip_df = df[["src_ip"]].copy()
    feature_df = df[feature_cols].copy()
    
    return src_ip_df, feature_df


def handle_missing_values(df: pd.DataFrame) -> pd.DataFrame:
    """Fill missing values with median."""
    if not df.isnull().values.any():
        return df

    df_clean = df.copy()
    medians = df_clean.median()
    df_clean.fillna(medians, inplace=True)
    logger.info(f"Filled {df.isnull().sum().sum()} missing values")

    return df_clean


def handle_infinite_values(df: pd.DataFrame) -> pd.DataFrame:
    """Replace infinite values with NaN then fill with median."""
    if not np.isinf(df.values).any():
        return df

    df_clean = df.copy()
    df_clean.replace([np.inf, -np.inf], np.nan, inplace=True)
    medians = df_clean.median()
    df_clean.fillna(medians, inplace=True)
    logger.info("Replaced infinite values")

    return df_clean


def rename_columns(df: pd.DataFrame, rename_map: Dict[str, str]) -> pd.DataFrame:
    """Rename columns according to mapping."""
    return df.rename(columns=rename_map)


def convert_to_float32(df: pd.DataFrame) -> pd.DataFrame:
    """Convert dataframe to float32 for memory efficiency."""
    return df.astype(np.float32)


def scale_features(df: pd.DataFrame, scaler: MinMaxScaler) -> pd.DataFrame:
    """Scale features using a pre-fitted MinMaxScaler."""
    scaled_data = scaler.transform(df)

    return pd.DataFrame(scaled_data, columns=df.columns, index=df.index)


# ============================================================================
# PIPELINE
# ============================================================================
def process_batch(
    raw_packet_df: pd.DataFrame, 
    scaler: MinMaxScaler,
    batch_size: int,
) -> pd.DataFrame:
    """
    Process a dataframe in batches through the full preprocessing pipeline.

    Args:
        raw_df: Raw input dataframe (never mutated)
        scaler: Pre-fitted MinMaxScaler
        batch_size: Number of rows to process per batch

    Returns:
        Fully processed dataframe with src_ip prepended
    """
    rename_map = COLUMN_RENAME_MAP
    processed_batches = []
    total_rows = 0

    try:
        for batch_num, i in enumerate(range(0, len(raw_packet_df), batch_size), start=1):
            batch = raw_packet_df.iloc[i : i + batch_size].copy()

            batch = clean_column_names(batch)
            feature_cols = list(rename_map.keys())
            src_ip_df, batch = select_numeric_columns(batch, feature_cols)
            batch = convert_to_float32(batch)
            batch = rename_columns(batch, rename_map)
            batch = handle_missing_values(batch)
            batch = handle_infinite_values(batch)
            batch = scale_features(batch, scaler)

            batch.insert(0, "src_ip", src_ip_df.reset_index(drop=True)["src_ip"])
            processed_batches.append(batch)

            total_rows += len(batch)
            logger.info(f"Processed batch {batch_num} ({total_rows} rows total)")

        if processed_batches:
            result_df = pd.concat(processed_batches, ignore_index=True)
            logger.info(f"Preprocessing complete. Total rows: {len(result_df)}")
            return result_df

        logger.warning("No data processed")
        return pd.DataFrame()

    except Exception as e:
        logger.error(f"Error during preprocessing: {str(e)}")
        raise


# ============================================================================
# SCALER PERSISTENCE
# ============================================================================

def save_scaler(scaler: MinMaxScaler, output_path: str) -> None:
    """Save fitted scaler to disk."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(scaler, output_path)
    logger.info(f"Scaler saved to {output_path}")


def load_scaler(scaler_path: str) -> MinMaxScaler:
    """Load fitted scaler from disk."""
    if not Path(scaler_path).exists():
        raise FileNotFoundError(f"Scaler not found at {scaler_path}")
    scaler = joblib.load(scaler_path)
    logger.info(f"Scaler loaded from {scaler_path}")
    return scaler


# ============================================================================
# PREPROCESSOR CLASS
# ============================================================================

class DDoSPreprocessor:
    """Production-ready preprocessor for DDoS detection."""

    def __init__(
        self,
        scaler_path: str,
        batch_size: int,
        raw_packet_queue: Queue[dict | None],
    ):
        self.scaler = load_scaler(scaler_path)
        self.batch_size = batch_size
        self.raw_packet_queue: Queue[dict | None] = raw_packet_queue
        self.cleaned_packet_queue: Queue[pd.DataFrame | None] = Queue()

    def get_queue(self) -> Queue[pd.DataFrame | None]:
        return self.cleaned_packet_queue

    def start(self):
        """
        Consume raw_packet_queue, batch packets, preprocess, and enqueue results.

        Stop conditions:
          - sentinel None received from upstream
          - Empty timeout with leftover buffer (flush then keep waiting)
          - Unrecoverable error in _flush_buffer
        """
        logger.info("Preprocessor started.")
        buffer = []

        while True:
            try:
                packet = self.raw_packet_queue.get(timeout=0.1)
                if packet is None:
                    if buffer:
                        logger.info(f"Flushing remaining {len(buffer)} packets.")
                        success = self.flush_buffer(buffer)
                        buffer = []
                        if not success:       
                            break
                        
                    self.cleaned_packet_queue.put(None)
                    logger.info("Preprocessor stopped.")
                    break

                buffer.append(packet)

                if len(buffer) >= self.batch_size:
                    logger.info(f"Flushing due to batch size (buffer: {len(buffer)})")
                    success = self.flush_buffer(buffer)
                    buffer = []
                    if not success:          
                        self.cleaned_packet_queue.put(None)
                        logger.info("Preprocessor stopped after flush error.")
                        break
            except Empty:
                if buffer:
                    logger.info(f"Flushing due to empty queue (buffer: {len(buffer)})")
                    success = self.flush_buffer(buffer)
                    buffer = []
                    if not success:
                        self.cleaned_packet_queue.put(None)
                        logger.info("Preprocessor stopped after flush error.")
                        break

    def flush_buffer(self, buffer: list) -> bool:
        """
        Convert buffer to DataFrame, preprocess, and enqueue result.

        Returns:
            True if successful, False on error
        """
        try:
            df = pd.DataFrame(buffer)
            processed_df = self.transform(df)
            self.cleaned_packet_queue.put(processed_df)
            logger.debug(f"Flushed batch of {len(buffer)} packets.")
            return True
        except Exception as e:
            logger.error(f"Error flushing buffer: {e}")
            return False

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Transform raw data using the fitted scaler.

        Args:
            df: Raw input dataframe

        Returns:
            Processed dataframe ready for model inference
        """
        return process_batch(df, self.scaler, self.batch_size)

    def save_scaler(self, output_path: str) -> None:
        """Save the fitted scaler to disk."""
        if self.scaler is None:
            raise ValueError("No scaler to save. Fit the preprocessor first.")
        save_scaler(self.scaler, output_path)