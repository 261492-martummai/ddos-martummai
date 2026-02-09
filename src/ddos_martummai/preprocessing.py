import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler
from typing import List, Dict, Tuple
import logging
from pathlib import Path
import joblib

logger = logging.getLogger("ddos-martummai")

# ============================================================================
# CONSTANTS
# ============================================================================

FEATURE_COLUMNS = [
    "Flow Duration",
    "Tot Fwd Pkts", 
    "Tot Bwd Pkts", 
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Fwd Pkt Len Std",
    "Bwd Pkt Len Min",
    "Bwd Pkt Len Std",
    "Flow IAT Min",
    "Fwd IAT Tot",
    "Fwd IAT Min",
    "Fwd PSH Flags",
    "Fwd Header Len",
    "Fwd Pkts/s",
    "SYN Flag Cnt",
    "ACK Flag Cnt",
    "URG Flag Cnt",
    "CWE Flag Count",
    "Init Fwd Win Byts",
    "Fwd Act Data Pkts",
    "Fwd Seg Size Min",
    "Active Mean",
    "Idle Mean",
]

COLUMN_RENAME_MAP = {
    'Tot Fwd Pkts': 'Total Fwd Packets', 
    'Tot Bwd Pkts': 'Total Backward Packets', 
    'TotLen Fwd Pkts': 'Total Length of Fwd Packets', 
    'TotLen Bwd Pkts': 'Total Length of Bwd Packets', 
    'Fwd Pkt Len Std': 'Fwd Packet Length Std', 
    'Bwd Pkt Len Min': 'Bwd Packet Length Min', 
    'Bwd Pkt Len Std': 'Bwd Packet Length Std', 
    'Flow IAT Min': 'Flow IAT Min', 
    'Fwd IAT Tot': 'Fwd IAT Total', 
    'Fwd IAT Min': 'Fwd IAT Min', 
    'Fwd Header Len': 'Fwd Header Length', 
    'Fwd Pkts/s': 'Fwd Packets/s', 
    'SYN Flag Cnt': 'SYN Flag Count', 
    'ACK Flag Cnt': 'ACK Flag Count', 
    'URG Flag Cnt': 'URG Flag Count', 
    'Init Fwd Win Byts': 'Init_Win_bytes_forward', 
    'Fwd Act Data Pkts': 'act_data_pkt_fwd', 
    'Fwd Seg Size Min': 'min_seg_size_forward',
}


# ============================================================================
# PURE FUNCTIONS
# ============================================================================

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


def scale_features(df: pd.DataFrame, scaler: MinMaxScaler = None) -> Tuple[pd.DataFrame, MinMaxScaler]:
    """
    Scale features using MinMaxScaler.
    
    Args:
        df: Input dataframe
        scaler: Pre-fitted scaler (for inference). If None, fit new scaler.
    
    Returns:
        Tuple of (scaled_df, scaler)
    """
    if scaler is None:
        scaler = MinMaxScaler()
        scaled_data = scaler.fit_transform(df)
    else:
        scaled_data = scaler.transform(df)
    
    scaled_df = pd.DataFrame(scaled_data, columns=df.columns, index=df.index)
    return scaled_df, scaler


# ============================================================================
# PIPELINE FUNCTIONS
# ============================================================================

def process_chunk(chunk: pd.DataFrame, 
                  feature_cols: List[str],
                  rename_map: Dict[str, str],
                  scaler: MinMaxScaler = None) -> Tuple[pd.DataFrame, MinMaxScaler]:
    """
    Process a single chunk through the complete pipeline.
    
    Args:
        chunk: Raw data chunk
        feature_cols: List of feature columns to select
        rename_map: Dictionary for renaming columns
        scaler: Pre-fitted scaler (for inference). If None, fit new scaler.
    
    Returns:
        Tuple of (processed_df, scaler)
    """
    df = clean_column_names(chunk)
    df = select_numeric_columns(df)
    df = select_feature_columns(df, feature_cols)
    df = convert_to_float32(df)
    df = handle_missing_values(df)
    df = handle_infinite_values(df)
    df = remove_duplicates(df)
    df = rename_columns(df, rename_map)
    df, scaler = scale_features(df, scaler)
    
    return df, scaler


def preprocess_csv_file(file_path: str, 
                        chunk_size: int = 1000,
                        feature_cols: List[str] = FEATURE_COLUMNS,
                        rename_map: Dict[str, str] = COLUMN_RENAME_MAP,
                        fit_scaler: bool = True) -> Tuple[pd.DataFrame, MinMaxScaler]:
    """
    Preprocess CSV file in chunks for training.
    
    Args:
        file_path: Path to CSV file
        chunk_size: Number of rows per chunk
        feature_cols: List of feature columns
        rename_map: Column rename mapping
        fit_scaler: Whether to fit a new scaler (True for training, False for inference)
    
    Returns:
        Tuple of (processed_df, fitted_scaler)
    """
    logger.info(f"Starting preprocessing of {file_path}")
    
    processed_chunks = []
    scaler = None
    total_rows = 0
    
    try:
        for i, chunk in enumerate(pd.read_csv(file_path, chunksize=chunk_size)):
            chunk_df, scaler = process_chunk(chunk, feature_cols, rename_map, scaler)
            processed_chunks.append(chunk_df)
            total_rows += len(chunk_df)
            
            if (i + 1) % 10 == 0:
                logger.info(f"Processed {i + 1} chunks ({total_rows} rows)")
        
        if processed_chunks:
            df = pd.concat(processed_chunks, ignore_index=True)
            logger.info(f"Preprocessing complete. Total rows: {len(df)}")
            return df, scaler
        else:
            logger.warning("No data processed")
            return pd.DataFrame(), None
            
    except Exception as e:
        logger.error(f"Error during preprocessing: {str(e)}")
        raise


def preprocess_realtime_data(df: pd.DataFrame,
                             scaler: MinMaxScaler,
                             feature_cols: List[str] = FEATURE_COLUMNS,
                             rename_map: Dict[str, str] = COLUMN_RENAME_MAP) -> pd.DataFrame:
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
    processed_df, _ = process_chunk(df, feature_cols, rename_map, scaler)
    return processed_df


# ============================================================================
# PRODUCTION UTILITIES
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


def validate_data_quality(df: pd.DataFrame, 
                          max_missing_ratio: float = 0.5,
                          max_duplicate_ratio: float = 0.3) -> Dict[str, bool]:
    """
    Validate data quality metrics.
    
    Args:
        df: Input dataframe
        max_missing_ratio: Maximum allowed ratio of missing values
        max_duplicate_ratio: Maximum allowed ratio of duplicates
    
    Returns:
        Dictionary of validation results
    """
    total_cells = df.shape[0] * df.shape[1]
    missing_ratio = df.isnull().sum().sum() / total_cells if total_cells > 0 else 0
    duplicate_ratio = df.duplicated().sum() / len(df) if len(df) > 0 else 0
    
    validation_results = {
        'has_data': len(df) > 0,
        'missing_ratio_ok': missing_ratio <= max_missing_ratio,
        'duplicate_ratio_ok': duplicate_ratio <= max_duplicate_ratio,
        'no_inf_values': not np.isinf(df.select_dtypes(include=[np.number]).values).any(),
        'missing_ratio': missing_ratio,
        'duplicate_ratio': duplicate_ratio
    }
    
    logger.info(f"Data quality: {validation_results}")
    return validation_results


# ============================================================================
# PRODUCTION EXAMPLE USAGE
# ============================================================================

class DDoSPreprocessor:
    """Production-ready preprocessor for DDoS detection."""
    
    def __init__(self, scaler_path: str = None):
        """
        Initialize preprocessor.
        
        Args:
            scaler_path: Path to saved scaler (for inference mode)
        """
        self.scaler = load_scaler(scaler_path) if scaler_path else None
        self.feature_cols = FEATURE_COLUMNS
        self.rename_map = COLUMN_RENAME_MAP
    
    def fit_transform(self, file_path: str, chunk_size: int = 1000) -> pd.DataFrame:
        """
        Fit scaler and transform training data.
        
        Args:
            file_path: Path to training CSV
            chunk_size: Chunk size for processing
        
        Returns:
            Processed training data
        """
        logger.info("Training mode: fitting scaler")
        df, self.scaler = preprocess_csv_file(
            file_path, 
            chunk_size, 
            self.feature_cols, 
            self.rename_map,
            fit_scaler=True
        )
        return df
    
    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Transform new data using fitted scaler (for inference).
        
        Args:
            df: Raw input data
        
        Returns:
            Processed data ready for model
        """
        if self.scaler is None:
            raise ValueError("Scaler not fitted. Call fit_transform first or load scaler.")
        
        logger.info("Inference mode: using fitted scaler")
        return preprocess_realtime_data(df, self.scaler, self.feature_cols, self.rename_map)
    
    def save_scaler(self, output_path: str) -> None:
        """Save the fitted scaler."""
        if self.scaler is None:
            raise ValueError("No scaler to save. Fit the preprocessor first.")
        save_scaler(self.scaler, output_path)
    
    def validate_input(self, df: pd.DataFrame) -> bool:
        """Validate input data quality."""
        results = validate_data_quality(df)
        return all([results['has_data'], 
                   results['missing_ratio_ok'], 
                   results['duplicate_ratio_ok'],
                   results['no_inf_values']])


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    # Training phase
    # print("=" * 80)
    # print("TRAINING PHASE")
    # print("=" * 80)
    
    # preprocessor = DDoSPreprocessor()
    
    # # Process training data
    # train_data = preprocessor.fit_transform(
    #     file_path='../../cic_output/2026-01-25_Flow.csv',
    #     chunk_size=1000
    # )
    
    # print(f"Processed training data shape: {train_data.shape}")
    # print(f"Columns: {list(train_data.columns)}")
    
    # # Save scaler for production use
    # preprocessor.save_scaler('models/scaler.joblib')
    
    # Save processed data
    # train_data.to_csv('processed_data/train_processed.csv', index=False)
    # print(f"Saved processed training data")
    
    print("\n" + "=" * 80)
    print("INFERENCE PHASE (Simulated)")
    print("=" * 80)
    
    # Load preprocessor with saved scaler for inference
    inference_preprocessor = DDoSPreprocessor(scaler_path='models/scaler.joblib')
    
    # Simulate real-time data (take first 100 rows as example)
    realtime_data = pd.read_csv('../../cic_output/2026-01-25_Flow.csv', nrows=100)
    
    # Validate and preprocess
    if inference_preprocessor.validate_input(realtime_data):
        processed_realtime = inference_preprocessor.transform(realtime_data)
        print(f"Processed real-time data shape: {processed_realtime.shape}")
        # Now ready for model.predict(processed_realtime)
    else:
        print("Data quality validation failed!")