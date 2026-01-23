import os
import sys

import click

from .config_loader import DEFAULT_CONFIG_DICT, load_config, validate_config
from .core import DDoSDetector
from .logger import setup_logger
from .setup_wizard import run_setup_wizard


@click.command()
@click.option(
    "--config",
    "-c",
    default="/etc/ddos-martummai/config.yml",
    help="Path to config file",
)
@click.option("--test-mode", "-t", is_flag=True, help="Enable test mode")
@click.option("--file", "-f", help="Input file path (.pcap or .csv) for test mode")
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
def main(config, test_mode, file, verbose):
    # 0. Setup Logger
    log_level = "DEBUG" if verbose else "INFO"
    setup_logger("/var/log/ddos-martummai/service.log", level=log_level)

    # 1. Fallback for Local Development (if not running from installed system path)
    if not os.path.exists(config):
        local_config = "config/config.yml"
        if os.path.exists(local_config):
            config = local_config

    # 2. Load Config
    app_config = load_config(config)

    # 3. Validation & Wizard Trigger
    if app_config is None or not validate_config(app_config):
        if sys.stdin.isatty():
            # Interactive Mode (User is running manually)
            success = run_setup_wizard(config, DEFAULT_CONFIG_DICT)
            if not success:
                sys.exit(1)
            # Reload after setup
            app_config = load_config(config)
        else:
            # Service Mode (Headless)
            print(f"[FATAL] Configuration invalid or missing at {config}")
            print("Please run 'ddos-martummai' manually to setup configuration first.")
            sys.exit(1)

    # 4. Initialize Detector
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


if __name__ == "__main__":
    main()
