import logging
from pathlib import Path
from queue import Queue
from typing import Dict, List

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler

from .util import constant

logger = logging.getLogger("PREPROCESSOR")


def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Strip whitespace from column names."""
    df_clean = df.copy()
    df_clean.columns = df_clean.columns.str.strip()
    return df_clean


def select_numeric_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Select only numeric columns from dataframe."""
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    return df[numeric_cols].copy()


def select_feature_columns(df: pd.DataFrame, columns: List[str]) -> pd.DataFrame:
    """Select specified feature columns."""
    missing_cols = set(columns) - set(df.columns)
    if missing_cols:
        logger.warning(f"Missing columns: {missing_cols}")
        available_cols = [col for col in columns if col in df.columns]
        return df[available_cols].copy()
    return df[columns].copy()


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


def remove_duplicates(df: pd.DataFrame) -> pd.DataFrame:
    """Remove duplicate rows."""
    initial_rows = len(df)
    df_clean = df.drop_duplicates().copy()
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
    scaled_data = scaler.transform(df)
    scaled_df = pd.DataFrame(scaled_data, columns=df.columns, index=df.index)

    return scaled_df


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
    feature_cols = constant.FEATURE_COLUMNS
    rename_map = constant.COLUMN_RENAME_MAP
    processed_chunks = []
    total_rows = 0

    try:
        for i, chunk in enumerate(df, chunksize=chunk_size):
            df = clean_column_names(chunk)
            df = select_numeric_columns(df)
            df = select_feature_columns(df, feature_cols)
            df = convert_to_float32(df)
            df = handle_missing_values(df)
            df = handle_infinite_values(df)
            df = remove_duplicates(df)
            df = rename_columns(df, rename_map)
            df = scale_features(df, scaler)

            processed_chunks.append(df)
            total_rows += len(df)
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

    def __init__(self, scaler_path: str, raw_packet_queue: Queue[dict | None]):
        self.scaler = load_scaler(scaler_path)
        self.raw_packet_queue: Queue[dict | None] = raw_packet_queue
        self.cleaned_packet_queue: Queue[dict | None] = Queue()

    def get_queue(self) -> Queue[dict | None]:
        return self.cleaned_packet_queue

    def start(self):
        while True:
            packet = self.raw_packet_queue.get()

            if packet is None:
                logger.info("Preprocessor Stopping...")
                self.cleaned_packet_queue.put(None)
                logger.info("Preprocessor Stopped.")
                break

            df = pd.DataFrame([packet])
            processed_df = self.transform(df)
            self.cleaned_packet_queue.put(processed_df.to_dict())

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
