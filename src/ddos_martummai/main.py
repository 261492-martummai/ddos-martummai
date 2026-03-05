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
from ddos_martummai.logger import setup_main_logger, setup_worker_logger
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


def run_reader(
    config, mode, out_queue, stop_event, log_queue, file_path=None, verbose=False
):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    setup_worker_logger(log_queue, logging.DEBUG if verbose else logging.INFO)
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


def run_preprocessor(
    scaler_path, batch_size, in_queue, out_queue, log_queue, verbose=False
):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    setup_worker_logger(log_queue, logging.DEBUG if verbose else logging.INFO)
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


def run_detector(
    model_path, config, in_queue, mitigation_event_queue, log_queue, verbose=False
):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    setup_worker_logger(log_queue, logging.DEBUG if verbose else logging.INFO)
    try:
        detector = DDoSDetector(
            model_path=model_path,
            config=config,
            cleaned_packet_queue=in_queue,
            mitigation_event_queue=mitigation_event_queue,
        )
        detector.start()
    except KeyboardInterrupt:
        pass


def check_privileges(setup_mode: bool):
    if not has_required_privileges(is_setup_mode=setup_mode):
        click.secho(
            "\nError: Insufficient privileges to run this mode!", fg="red", bold=True
        )
        if setup_mode:
            click.secho("   Setup mode requires root privileges.", fg="yellow")
        else:
            click.secho(
                "   Real-time Monitor requires elevated permissions.", fg="yellow"
            )
            click.secho(
                "   (Must be run as 'root' or systemd service user).",
                fg="yellow",
            )
        click.secho("   Please run with: ", nl=False, fg="yellow")
        click.secho(f"sudo {' '.join(sys.argv)}", fg="green", bold=True)
        sys.exit(1)


def start_web_server(mitigation_queue: Queue):
    NM_PORT = int(os.getenv("NM_PORT", "8000"))
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
    monitor.set_mitigation_queue(mitigation_queue)
    monitor.start()


def monitor_processes(mode, processes, logger):
    p_reader, p_prep, p_det = processes
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

    # Set umask to 007 (resulting in 660 file permissions).
    # This ensures that ALL files spawned by this application grant read/write
    # permissions to both 'root' (Owner) and the 'ddos-martummai' user (Group),
    # while blocking access from other unauthorized users.
    os.umask(0o007)

    # Setup Program Mode and Privileges
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
        check_privileges(setup)

    # Setup Wizard Mode
    if setup:
        wizard = SetupWizard(config_file, AppConfig())
        success = wizard.run()
        if success:
            sys.exit(0)
        else:
            sys.exit(1)

    # 1. Load Config First
    loader = DDoSConfigLoader(config_file, override_env, test_mode)
    app_config = loader.load()

    # 2. Setup Logging
    log_level = logging.DEBUG if verbose else logging.INFO
    log_queue, log_listener = setup_main_logger(
        level=log_level,
        log_file_path=app_config.system.log_file_path,
        test_mode=test_mode,
    )
    log_listener.start()

    logger = logging.getLogger("MAIN")
    logger.info("Starting DDoS Martummai Guard System...")
    logger.info(f"Initializing modules in mode: {mode}")

    # 3. Find model and scaler paths relative to this file
    current_dir = Path(__file__).parent.resolve()
    ml_dir = current_dir / "ml"
    model_path = ml_dir / "model.joblib"
    scaler_path = ml_dir / "scaler.joblib"

    # 4. Setup multiprocessing queues and events
    mitigation_event_queue = Queue(maxsize=1000)
    raw_packet_queue = Queue(maxsize=100000)
    cleaned_packet_queue = Queue(maxsize=50000)
    stop_event = Event()

    if mode == "live":
        start_web_server(mitigation_event_queue)

    # 5. Start worker processes
    reader_args = (
        app_config,
        mode,
        raw_packet_queue,
        stop_event,
        log_queue,
        file_path,
        verbose,
    )
    prep_args = (
        scaler_path,
        app_config.model.batch_size,
        raw_packet_queue,
        cleaned_packet_queue,
        log_queue,
        verbose,
    )
    det_args = (
        model_path,
        app_config,
        cleaned_packet_queue,
        mitigation_event_queue,
        log_queue,
        verbose,
    )

    p_reader = Process(target=run_reader, args=reader_args, name="ReaderProcess")
    p_prep = Process(target=run_preprocessor, args=prep_args, name="PrepProcess")
    p_det = Process(target=run_detector, args=det_args, name="DetProcess")

    logger.info("Starting worker processes...")
    processes = (p_reader, p_prep, p_det)
    for p in processes:
        p.start()

    try:
        monitor_processes(mode, processes, logger)
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

        for p in processes:
            p.join()

        logger.info("--- All systems shutdown safely ---")
        if isinstance(e, RuntimeError):
            sys.exit(1)
    finally:
        log_listener.stop()


if __name__ == "__main__":
    freeze_support()
    main()
