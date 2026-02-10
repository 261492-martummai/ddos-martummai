import sys
from pathlib import Path

import click

from ddos_martummai.reader import Reader
from ddos_martummai.preprocessor import DDoSPreprocessor
from ddos_martummai.detector import DDoSDetector


from .config_loader import (
    load_config,
)
from .logger import setup_logger
from .setup_wizard import run_setup_wizard
import threading
import time


@click.command()
@click.option("--config", "-c", default="config/config.yml", help="Path to config file")
@click.option("--test-mode", "-t", is_flag=True, help="Enable test mode")
@click.option("--file-path", "-f", help="Input file path (.pcap or .csv) for test mode")
@click.option(
    "--override-env",
    "-o",
    is_flag=True,
    help="Override existing config form enironment variables",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
def main(config, test_mode, file_path, override_env, verbose):
    
    # 1. Load Config First
    app_config = load_config(config, override_env_vars=override_env)
    
    # 2. Setup Logger
    log_level = "DEBUG" if verbose else "INFO"
    if app_config and app_config.system.log_file_path:
        log_path = app_config.system.log_file_path
        # Ensure directory exists (safe check)
        try:
            Path(log_path).parent.mkdir(parents=True, exist_ok=True)
            setup_logger(log_path, level=log_level)
            if verbose:
                print(f"Logging initialized at: {log_path}")
        except PermissionError:
            print(f"[!] Permission Denied: Cannot write logs to {log_path}")
            print("[!] Falling back to console output only.")
            setup_logger(None, level=log_level)
    else:
        # Fallback if config failed completely
        setup_logger(None, level=log_level)
        
    # 3. Validation & Wizard Trigger
    if app_config is None:
        if sys.stdin.isatty():
            # Interactive Mode (User is running manually)
            base_config_for_wizard = {}

            success = run_setup_wizard(config, base_config_for_wizard)
            if not success:
                sys.exit(1)
            # Reload after setup
            app_config = load_config(config, override_env_vars=override_env)

        else:
            # Service Mode (Headless)
            print(f"[FATAL] Configuration invalid or missing at {config}")
            print("Please run 'ddos-martummai' manually to setup configuration first.")
            sys.exit(1)

    # 4. Find model and scaler paths relative to this file
    current_dir = Path(__file__).parent.resolve()
    model_dir = current_dir / "models"
    model_path = model_dir / "model.joblib"
    scaler_path = model_dir / "scaler.joblib"

    mode: str = "live"
    if test_mode:
        if not file_path:
            click.echo("Error: --file is required for test mode")
            return
        if file_path.endswith(".pcap"):
            mode="pcap"
        elif file_path.endswith(".csv"):
            mode="csv"
        else:
            click.echo("Error: Unsupported file format. Use .pcap or .csv")

    # 5. Initialize
    reader = Reader(app_config, mode)
    preprocessor = DDoSPreprocessor(
        scaler_path,
        reader.get_queue() # get Queue from Preprocessor
    )
    
    detector = DDoSDetector(
        model_path,
        app_config,
        preprocessor.get_queue()
    )
    
    t_reader = threading.Thread(target=reader.start)
    t_prep = threading.Thread(target=preprocessor.start)
    t_det = threading.Thread(target=detector.start)
    
    t_det.start()
    t_prep.start()
    t_reader.start()
    
    try:
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n!!! Keyboard Interrupt Detected !!!")
        reader.stop()
        t_reader.join()
        t_prep.join()
        t_det.join()
        print("--- All systems shutdown safely ---")
    
'''
    # 1. Load Config First
    # We need the config to know WHERE to write the logs
    app_config = load_config(config, override_env_vars=override_env)

    # 2. Setup Logger
    log_level = "DEBUG" if verbose else "INFO"
    if app_config and app_config.system.log_file_path:
        log_path = app_config.system.log_file_path
        # Ensure directory exists (safe check)
        try:
            Path(log_path).parent.mkdir(parents=True, exist_ok=True)
            setup_logger(log_path, level=log_level)
            if verbose:
                print(f"Logging initialized at: {log_path}")
        except PermissionError:
            print(f"[!] Permission Denied: Cannot write logs to {log_path}")
            print("[!] Falling back to console output only.")
            setup_logger(None, level=log_level)
    else:
        # Fallback if config failed completely
        setup_logger(None, level=log_level)

    # 3. Validation & Wizard Trigger
    if app_config is None:
        if sys.stdin.isatty():
            # Interactive Mode (User is running manually)
            base_config_for_wizard = {}

            success = run_setup_wizard(config, base_config_for_wizard)
            if not success:
                sys.exit(1)
            # Reload after setup
            app_config = load_config(config, override_env_vars=override_env)

        else:
            # Service Mode (Headless)
            print(f"[FATAL] Configuration invalid or missing at {config}")
            print("Please run 'ddos-martummai' manually to setup configuration first.")
            sys.exit(1)

    # 4. Initialize
    reader = Reader(app_config)
    preprocessor = DDoSPreprocessor(scaler_path="models/scaler.joblib")
    detector = DDoSDetector(app_config)

    # 5. Run Mode Selection
    if test_mode:
        if not file:
            click.echo("Error: --file is required for test mode")
            return

        if file.endswith(".pcap"):
            detector.start_monitoring(mode="pcap", input_file=file)
        elif file.endswith(".csv"):
            detector.start_monitoring(mode="csv", input_file=file)
        else:
            click.echo("Error: Unsupported file format. Use .pcap or .csv")
    else:
        click.echo(f"Starting Live Monitoring on {app_config.system.interface}...")
        detector.start_monitoring(mode="live")

'''
if __name__ == "__main__":
    main()
