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

    mode = "live"
    if test_mode:
        if not file_path:
            click.echo("Error: --file is required for test mode")
            return

        file_path = Path(file_path)
        if not file_path.exists():
            click.echo(f"Error: File not found at {file_path}")
            return

        if file_path.suffix == ".pcap":
            mode = "pcap"
        elif file_path.suffix == ".csv":
            mode = "csv"
        else:
            click.echo("Error: Unsupported file format. Use .pcap or .csv")

    logger.info(f"Initializing modules in mode: {mode}")

    # 5. Initialize
    reader = Reader(app_config, mode)
    preprocessor = DDoSPreprocessor(
        scaler_path,
        app_config.model.batch_size,
        reader.get_queue(),  # get Queue from Reader
    )
    detector = DDoSDetector(model_path, app_config, preprocessor.get_queue())

    if mode == "live":
        t_reader = threading.Thread(target=reader.start)
    else:
        t_reader = threading.Thread(target=reader.start, args=(file_path,))
    t_prep = threading.Thread(target=preprocessor.start)
    t_det = threading.Thread(target=detector.start)

    logger.info("Starting worker threads...")
    t_det.start()
    t_prep.start()
    t_reader.start()

    try:
        while True:
            time.sleep(1)

            reader_died = not t_reader.is_alive()
            prep_died = not t_prep.is_alive()
            det_died = not t_det.is_alive()

            if mode == "live":
                if reader_died or prep_died or det_died:
                    logger.critical(
                        "CRITICAL ERROR: A core service thread has died unexpectedly!"
                    )
                    if reader_died:
                        logger.critical(" -> Reader Service: DEAD")
                    if prep_died:
                        logger.critical(" -> Preprocessor Service: DEAD")
                    if det_died:
                        logger.critical(" -> Detector Service: DEAD")

                    raise RuntimeError("System integrity compromised.")

            else:
                if det_died:
                    logger.info("File processing completed (Detector finished).")
                    break

                if prep_died and not reader_died:
                    logger.warning("Preprocessor died prematurely!")

    except (KeyboardInterrupt, RuntimeError) as e:
        if isinstance(e, RuntimeError):
            logger.error(f"Initiating EMERGENCY SHUTDOWN due to: {e}")
        else:
            logger.warning("Keyboard Interrupt detected. Stopping...")

        logger.info("Stopping DDoS Guard Service...")
        reader.stop()

        if isinstance(e, RuntimeError):
            try:
                reader.get_queue().put(None)
            except Exception as ex:
                logger.error(f"Failed to inject poison pill: {ex}")

        logger.info("Waiting for worker threads to finish")

        t_reader.join()
        t_prep.join()
        t_det.join()

        logger.info("--- All systems shutdown safely ---")
        if isinstance(e, RuntimeError):
            exit(1)


if __name__ == "__main__":
    main()