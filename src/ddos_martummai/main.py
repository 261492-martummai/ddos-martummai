import logging
import threading
import time
from pathlib import Path

import click

from ddos_martummai.config_loader import DDoSConfigLoader
from ddos_martummai.detector import DDoSDetector
from ddos_martummai.preprocessor import DDoSPreprocessor
from ddos_martummai.reader import Reader

logger = logging.getLogger("MAIN")


@click.command()
@click.option("--config-path", "-c", default=None, help="Path to config file")
@click.option("--test-mode", "-t", is_flag=True, help="Enable test mode")
@click.option("--file-path", "-f", help="Input file path (.pcap or .csv) for test mode")
@click.option(
    "--override-env",
    "-o",
    is_flag=True,
    help="Override existing config form enironment variables",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
def main(config_path, test_mode, file_path, override_env, verbose):
    # 1. Load Config First
    loader = DDoSConfigLoader(config_path, override_env)
    app_config = loader.app_config

    logger.info("Starting DDoS Martummai Guard System...")

    # 4. Find model and scaler paths relative to this file
    current_dir = Path(__file__).parent.resolve()
    model_dir = current_dir / "models"
    model_path = model_dir / "model.joblib"
    scaler_path = model_dir / "scaler.joblib"

    mode = "csv"
    if test_mode:
        if not file_path:
            click.echo("Error: --file is required for test mode")
            return
        if file_path.endswith(".pcap"):
            mode = "pcap"
        elif file_path.endswith(".csv"):
            mode = "csv"
        else:
            click.echo("Error: Unsupported file format. Use .pcap or .csv")

    logger.info(f"Initializing modules in mode: {mode}")

    # 5. Initialize
    reader = Reader(app_config, mode)
    preprocessor = DDoSPreprocessor(
        scaler_path,
        reader.get_queue(),  # get Queue from Preprocessor
    )

    detector = DDoSDetector(model_path, app_config, preprocessor.get_queue())

    t_reader = threading.Thread(target=reader.start)
    t_prep = threading.Thread(target=preprocessor.start)
    t_det = threading.Thread(target=detector.start)

    logger.info("Starting worker threads...")
    # t_det.start()
    # t_prep.start()
    # t_reader.start()
    t_reader.start()
    t_reader.join()   # wait until reader finishes

    t_prep.start()
    t_prep.join()     # wait until preprocessor finishes

    t_det.start()
    t_det.join()      # wait until detector finishes

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        logger.warning("Keyboard Interrupt detected. Shutting down...")
        logger.info("Stopping DDoS Guard Service...")
        reader.stop()

        t_reader.join()
        t_prep.join()
        t_det.join()
        logger.info("--- All systems shutdown safely ---")


if __name__ == "__main__":
    main()
