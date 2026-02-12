import logging
from pathlib import Path
from queue import Empty, Queue
from typing import Dict

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler

from ddos_martummai.init_models import AppConfig
from ddos_martummai.util.constant import COLUMN_RENAME_MAP

logger = logging.getLogger("PREPROCESSOR")

IP_COLUMN_NAME = "Source IP"
numeric_columns = [col for col in COLUMN_RENAME_MAP.values() if col != IP_COLUMN_NAME]


def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Strip whitespace from column names and normalize to lowercase with underscores."""
    df.columns = df.columns.str.strip()
    return df


def select_numeric_columns(df: pd.DataFrame, feature_cols: list) -> pd.DataFrame:
    """Select only numeric columns from dataframe."""
    return df[feature_cols].copy()


def handle_missing_values(df: pd.DataFrame) -> pd.DataFrame:
    """Fill missing values with median."""
    if not df.isnull().values.any():
        return df

    logger.info(f"Filled {df.isnull().sum().sum()} missing values")

    return df.fillna(df.median())


def handle_infinite_values(df: pd.DataFrame) -> pd.DataFrame:
    """Replace infinite values with NaN then fill with median."""
    if not np.isinf(df.values).any():
        return df

    df_clean = df.replace([np.inf, -np.inf], np.nan)
    medians = df_clean.median()
    logger.info("Replaced infinite values")

    return df_clean.fillna(medians)


def remove_duplicates(df: pd.DataFrame) -> pd.DataFrame:
    """Remove duplicate rows."""
    initial_rows = len(df)

    df_clean = df.drop_duplicates()

    removed = initial_rows - len(df_clean)
    if removed > 0:
        logger.info(f"Removed {removed} duplicate rows")

    return df_clean


def rename_columns(df: pd.DataFrame, rename_map: Dict[str, str]) -> pd.DataFrame:
    """Rename columns according to mapping."""
    return df.rename(columns=rename_map)


def convert_to_float32(df: pd.DataFrame) -> pd.DataFrame:
    """Convert dataframe to float32 for memory efficiency."""
    return df.astype(np.float32)


def scale_features(df: pd.DataFrame, scaler: MinMaxScaler) -> pd.DataFrame:
    """
    Scale features using MinMaxScaler.

    Args:
        df: Input dataframe
        scaler: Pre-fitted scaler (for inference). If None, fit new scaler.

    Returns:
        Scaled dataframe
    """
    try:
        scaled_data = scaler.transform(df)
    except ValueError as e:
        logger.warning(f"Scaler feature mismatch, attempting to align: {e}")
        common_cols = [c for c in scaler.feature_names_in_ if c in df.columns]
        if not common_cols:
            raise ValueError("No common columns found between data and scaler")
        scaled_data = scaler.transform(df[common_cols])
        df = df[common_cols]

    return pd.DataFrame(scaled_data, columns=df.columns, index=df.index)


def process_chunk(
    df: pd.DataFrame,
    scaler: MinMaxScaler,
    chunk_size: int = 1000,
) -> pd.DataFrame:
    """
    Process a single chunk through the complete pipeline.

    Args:
        df: Raw data dataframe
        feature_cols: List of feature columns to select
        rename_map: Dictionary for renaming columns
        scaler: Pre-fitted scaler (for inference). If None, fit new scaler.

    Returns:
        Tuple of (processed_df, scaler)
    """
    rename_map = COLUMN_RENAME_MAP
    processed_chunks = []
    total_rows = 0

    try:
        for i in range(0, len(df), chunk_size):
            chunk = df.iloc[i : i + chunk_size]
            df = clean_column_names(chunk)
            df = select_numeric_columns(df, list(rename_map.keys()))
            df = rename_columns(df, rename_map)

            df = remove_duplicates(df)
            if df.empty:
                continue

            ip_series = None
            if IP_COLUMN_NAME in df.columns:
                ip_series = df[IP_COLUMN_NAME]
                feat_df = df.drop(columns=[IP_COLUMN_NAME])
            else:
                feat_df = df.copy()

            feat_df = convert_to_float32(feat_df)
            feat_df = handle_missing_values(feat_df)
            feat_df = handle_infinite_values(feat_df)
            feat_df = scale_features(feat_df, scaler)

            feat_df[IP_COLUMN_NAME] = ip_series

            processed_chunks.append(feat_df)
            total_rows += len(feat_df)

            logger.info(f"Processed {i + 1} chunks ({total_rows} rows)")

        if processed_chunks:
            df = pd.concat(processed_chunks, ignore_index=True)
            logger.info(f"Preprocessing complete. Total rows: {len(df)}")
            return df
        else:
            logger.warning("No data processed")
            return pd.DataFrame()
    except Exception as e:
        logger.error(f"Error during preprocessing: {str(e)}")
        raise


def preprocess_realtime_data(
    df: pd.DataFrame,
    scaler: MinMaxScaler,
) -> pd.DataFrame:
    """
    Preprocess real-time data for inference using pre-fitted scaler.

    Args:
        df: Raw input dataframe
        scaler: Pre-fitted scaler from training
        feature_cols: List of feature columns
        rename_map: Column rename mapping

    Returns:
        Processed dataframe ready for model inference
    """
    processed_df = process_chunk(df, scaler)
    return processed_df


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


class DDoSPreprocessor:
    """Production-ready preprocessor for DDoS detection."""

    def __init__(
        self,
        scaler_path: str,
        app_config: AppConfig,
        raw_packet_queue: Queue[dict | None],
    ):
        self.scaler = load_scaler(scaler_path)
        self.raw_packet_queue: Queue[dict | None] = raw_packet_queue
        self.cleaned_packet_queue: Queue[pd.DataFrame | None] = Queue()
        self.BATCH_SIZE = app_config.model.batch_size

    def get_queue(self) -> Queue[pd.DataFrame | None]:
        return self.cleaned_packet_queue

    def start(self):
        buffer = []

        while True:
            try:
                packet = self.raw_packet_queue.get(timeout=0.1)

                if packet is None:
                    if buffer:
                        self._flush_buffer(buffer)
                    self.cleaned_packet_queue.put(None)
                    logger.info("Preprocessor Stopped.")
                    break

                buffer.append(packet)

                if len(buffer) >= self.BATCH_SIZE:
                    logger.info(f"Flushing due to batch size (Buffer: {len(buffer)})")
                    self._flush_buffer(buffer)
                    buffer = []
                    continue

            except Empty:
                if buffer:
                    logger.info(
                        f"Flushing due to Empty Queue pipe (Buffer: {len(buffer)})"
                    )
                    self._flush_buffer(buffer)
                    buffer = []

    def _flush_buffer(self, buffer):
        try:
            df = pd.DataFrame(buffer)

            processed_df = self.transform(df)

            self.cleaned_packet_queue.put(processed_df)

            logger.debug(f"Flushed batch of {len(buffer)} packets")
        except Exception as e:
            logger.error(f"Error flushing buffer: {e}")

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Transform new data using fitted scaler (for inference).

        Args:
            df: Raw input data

        Returns:
            Processed data ready for model
        """
        logger.info("Inference mode: using fitted scaler")
        return preprocess_realtime_data(df, self.scaler)

    def save_scaler(self, output_path: str) -> None:
        """Save the fitted scaler."""
        if self.scaler is None:
            raise ValueError("No scaler to save. Fit the preprocessor first.")
        save_scaler(self.scaler, output_path)
