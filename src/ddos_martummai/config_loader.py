import logging
import os
import shutil
import sys
from dataclasses import fields
from pathlib import Path

import yaml

from ddos_martummai.init_models import (
    AppConfig,
    MitigationConfig,
    ModelConfig,
    SystemConfig,
)
from ddos_martummai.logger import attach_file_logging
from ddos_martummai.setup_wizard import SetupWizard
from ddos_martummai.util.path_helper import get_app_paths

logger = logging.getLogger("CONFIG")
APP_PATHS = get_app_paths()


class DDoSConfigLoader:
    def __init__(self, config_file: Path, override_env: bool = False):
        self.config_file = config_file
        self.override_env = override_env
        self.app_config: AppConfig = AppConfig()

        logger.info("Load Configuration")

        self._ensure_config_file_exists()
        self._load_app_config()
        self._inject_system_paths()
        self._check_override_env()
        self._validate_config()
        self._setup_logger()

        logger.info("Configuration Loaded Successfully")

    def _ensure_config_file_exists(self):
        if self.config_file.exists():
            return

        logger.warning(f"Config not found: {self.config_file}")

        self.config_file.parent.mkdir(parents=True, exist_ok=True)

        if APP_PATHS["template_config"].exists():
            logger.info("Copying from template...")
            shutil.copy(APP_PATHS["template_config"], self.config_file)
        else:
            logger.info("Creating from internal defaults...")
            with open(self.config_file, "w") as f:
                yaml.dump(AppConfig(), f)

    def _load_app_config(self):
        with open(self.config_file) as f:
            raw = yaml.safe_load(f) or {}

        self.app_config = AppConfig(
            system=SystemConfig(**raw.get("system", {})),
            model=ModelConfig(**raw.get("model", {})),
            mitigation=MitigationConfig(**raw.get("mitigation", {})),
        )

    def _inject_system_paths(self):
        data_dir = APP_PATHS["data_dir"]
        log = APP_PATHS["log_file"]
        data_dir.mkdir(exist_ok=True)
        log.parent.mkdir(parents=True, exist_ok=True)

        if not self.app_config.system.csv_output_path:
            self.app_config.system.csv_output_path = str(data_dir / "flow_logs.csv")

        if not self.app_config.system.test_mode_output_path:
            self.app_config.system.test_mode_output_path = str(
                data_dir / "test_results.csv"
            )

        if not self.app_config.system.log_file_path:
            self.app_config.system.log_file_path = str(log)

    def _check_override_env(self):
        if not self.override_env:
            return

        target_configs = [
            self.app_config.system,
            self.app_config.model,
            self.app_config.mitigation,
        ]

        prefix = "DDOS_MARTUMMAI_"

        for config in target_configs:
            for env_field in fields(config):
                env_key = f"{prefix}{env_field.name.upper()}"
                env_value = os.getenv(env_key)

                if env_value is not None:
                    try:
                        if env_field.type is int:
                            val = int(env_value)
                        elif env_field.type is bool:
                            val = env_value.lower() in ("true", "1")
                        else:
                            val = env_value

                        setattr(config, env_field.name, val)

                    except ValueError:
                        logger.error(
                            f"Warning: Invalid value for {env_key}, expected {env_field.type}"
                        )

    def _validate_config(self):
        errors = []
        cfg = self.app_config

        # 1. System Config Validation
        if not cfg.system.interface:
            errors.append("System Interface is required")

        # 2. Mitigation Config Validation
        mit = cfg.mitigation
        if not mit.admin_email:
            errors.append("Admin Email is required")

        if mit.admin_email:
            if not mit.smtp_user:
                errors.append("SMTP User is required")
            if not mit.smtp_password:
                errors.append("SMTP Password is required")

        for error in errors:
            logger.warning(f"Config Validator: {error}")

        if errors:
            # Interactive Mode (User is running manually on Terminal)
            if sys.stdin.isatty():
                print("\n[!] Configuration incomplete.")
                wizard = SetupWizard(self.config_file, self.app_config)
                success = wizard.run()

                if not success:
                    print("Setup cancelled.")
                    sys.exit(1)

                print("[*] Configuration updated. Resuming startup...\n")
                return

            else:
                # Service Mode (Headless / Background Process)
                logger.critical(f"[FATAL] Configuration invalid at {self.config_file}")
                logger.critical(f"Missing fields: {', '.join(errors)}")
                logger.critical(
                    "Please run 'ddos-martummai' manually to setup configuration first."
                )
                sys.exit(1)

    def _setup_logger(self):
        log_path = self.app_config.system.log_file_path
        if log_path:
            attach_file_logging(log_path)
        else:
            logger.warning("No log file path configured. Logging to console only.")
