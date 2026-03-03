import logging
import os
import signal
import sys
import threading
import time
from multiprocessing import Event, Process, Queue, freeze_support
from pathlib import Path

import click
import uvicorn
from click_option_group import optgroup

from ddos_martummai.config_loader import DDoSConfigLoader
from ddos_martummai.detector import DDoSDetector
from ddos_martummai.init_models import AppConfig
from ddos_martummai.logger import get_console_logger
from ddos_martummai.logger import setup_uvicorn_logging as uvicorn_log
from ddos_martummai.preprocessor import DDoSPreprocessor
from ddos_martummai.reader import Reader
from ddos_martummai.setup_wizard import SetupWizard
from ddos_martummai.util.constant import CONTEXT_SETTINGS
from ddos_martummai.util.os_checker import has_required_privileges
from ddos_martummai.util.path_helper import get_app_paths
from ddos_martummai.web import monitor
from ddos_martummai.web.monitor import app

APP_PATHS = get_app_paths()


def run_reader(config, mode, out_queue, stop_event, file_path=None, verbose=False):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    get_console_logger(logging.DEBUG if verbose else logging.INFO)

    try:
        reader = Reader(
            config=config, mode=mode, raw_packet_queue=out_queue, stop_event=stop_event
        )
        if mode == "live":
            reader.start()
        else:
            reader.start(file_path)
    except KeyboardInterrupt:
        pass


def run_preprocessor(scaler_path, batch_size, in_queue, out_queue, verbose=False):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    get_console_logger(logging.DEBUG if verbose else logging.INFO)

    try:
        preprocessor = DDoSPreprocessor(
            scaler_path=scaler_path,
            batch_size=batch_size,
            raw_packet_queue=in_queue,
            cleaned_packet_queue=out_queue,
        )
        preprocessor.start()
    except KeyboardInterrupt:
        pass


def run_detector(model_path, config, in_queue, verbose=False):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    get_console_logger(logging.DEBUG if verbose else logging.INFO)

    try:
        detector = DDoSDetector(
            model_path=model_path, config=config, cleaned_packet_queue=in_queue
        )
        detector.start()
    except KeyboardInterrupt:
        pass


@click.command(context_settings=CONTEXT_SETTINGS)
# Group 1: Modes
@optgroup.group("Modes (Default: Real-time Monitor)")
@optgroup.option(
    "-t", "--test-mode", is_flag=True, help="Run in Test/Simulation mode (requires -f)."
)
@optgroup.option("--setup", is_flag=True, help="Run the initial setup wizard and exit.")
# Group 2: Test Arguments
@optgroup.group("Test Arguments", help="(Required for --test-mode)")
@optgroup.option(
    "-f",
    "--file-path",
    metavar="FILE",
    type=click.Path(exists=True),
    help="Input pcap or csv file path for testing.",
)
# Group 3: Configuration
@optgroup.group("Configuration Options")
@optgroup.option(
    "-c",
    "--config-file",
    metavar="FILE",
    type=click.Path(exists=True),
    help="Path to configuration file.",
)
@optgroup.option(
    "-o",
    "--override-env",
    is_flag=True,
    help="Override config with Environment Variables.",
)
# Group 4: General
@optgroup.group("General Options")
@optgroup.option("-v", "--verbose", is_flag=True, help="Enable debug logging.")
def main(config_file, test_mode, file_path, override_env, setup, verbose):
    """
    DDoS MarTumMai Guard: A Fine-Tuned Machine Learning DDoS detection system.
    """
    config_file = Path(config_file) if config_file else APP_PATHS["config_file"]

    mode = "live"
    if test_mode:
        if not file_path:
            click.echo("Error: --file is required for test mode")
            sys.exit(1)

        file_path = Path(file_path)
        if not file_path.exists():
            click.echo(f"Error: File not found at {file_path}")
            sys.exit(1)

        if file_path.suffix == ".pcap":
            mode = "pcap"
        elif file_path.suffix == ".csv":
            mode = "csv"
        else:
            click.echo("Error: Unsupported file format. Use .pcap or .csv")
            sys.exit(1)
    else:
        # Check privileges dynamically based on the 'setup' flag
        if not has_required_privileges(is_setup_mode=setup):
            click.secho(
                "\nError: Insufficient privileges to run this mode!",
                fg="red",
                bold=True,
            )

            # Show specific error messages to guide the user
            if setup:
                click.secho(
                    "   Setup mode requires root privileges to write configuration files.",
                    fg="yellow",
                )
            else:
                click.secho(
                    "   Real-time Monitor captures live network packets, which requires elevated permissions.",
                    fg="yellow",
                )
                click.secho(
                    "   (Must be run as 'root' or the 'ddos-martummai' systemd service user).",
                    fg="yellow",
                )

            click.secho("   Please run with: ", nl=False, fg="yellow")
            click.secho(f"sudo {' '.join(sys.argv)}", fg="green", bold=True)
            sys.exit(1)

    if setup:
        wizard = SetupWizard(config_file, AppConfig())
        success = wizard.run()
        if success:
            sys.exit(0)
        else:
            sys.exit(1)

    logger = get_console_logger(logging.DEBUG if verbose else logging.INFO)
    logger.name = "MAIN"
    logger.info("Starting DDoS Martummai Guard System...")

    # 1. Load Config First
    loader = DDoSConfigLoader(config_file, override_env, test_mode)
    app_config = loader.load()

    # 2. Find model and scaler paths relative to this file
    current_dir = Path(__file__).parent.resolve()
    ml_dir = current_dir / "ml"
    model_path = ml_dir / "model.joblib"
    scaler_path = ml_dir / "scaler.joblib"

    logger.info(f"Initializing modules in mode: {mode}")

    # 3. Initialize modules and threads
    NM_PORT: int = int(os.getenv("NM_PORT", "8000"))
    t_web = threading.Thread(
        target=lambda: uvicorn.run(
            app,
            host="0.0.0.0",  # nosec B104
            port=NM_PORT,
            log_config=uvicorn_log(),
        ),
        daemon=True,
    )
    t_web.start()
    monitor.start()

    raw_packet_queue = Queue(maxsize=20000)
    cleaned_packet_queue = Queue(maxsize=20000)

    stop_event = Event()

    reader_args = (app_config, mode, raw_packet_queue, stop_event, file_path, verbose)
    prep_args = (
        scaler_path,
        app_config.model.batch_size,
        raw_packet_queue,
        cleaned_packet_queue,
        verbose,
    )
    det_args = (model_path, app_config, cleaned_packet_queue, verbose)

    p_reader = Process(target=run_reader, args=reader_args, name="ReaderProcess")
    p_prep = Process(target=run_preprocessor, args=prep_args, name="PrepProcess")
    p_det = Process(target=run_detector, args=det_args, name="DetProcess")

    logger.info("Starting worker processes...")
    p_det.start()
    p_prep.start()
    p_reader.start()

    try:
        while True:
            time.sleep(1)

            reader_died = not p_reader.is_alive()
            prep_died = not p_prep.is_alive()
            det_died = not p_det.is_alive()

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
        stop_event.set()

        if isinstance(e, RuntimeError):
            try:
                raw_packet_queue.put(None)
            except Exception as ex:
                logger.error(f"Failed to inject poison pill: {ex}")

        logger.info("Waiting for worker processes to finish")

        p_reader.join()
        p_prep.join()
        p_det.join()

        logger.info("--- All systems shutdown safely ---")
        if isinstance(e, RuntimeError):
            sys.exit(1)


if __name__ == "__main__":
    freeze_support()
    main()
