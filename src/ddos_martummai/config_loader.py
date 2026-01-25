import logging
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DEFAULT_CONFIG_PATH = BASE_DIR / "config/config.yml"
TEMPLATE_CONFIG_PATH = BASE_DIR / "config/config.example.yml"

# Default Template for regeneration
DEFAULT_CONFIG_DICT = {
    "system": {
        "interface": None,
        "csv_output_path": None,
        "test_mode_output_path": None,
        "log_file_path": None,
    },
    "model": {"batch_size": 1000},
    "mitigation": {
        "enable_blocking": False,
        "block_duration_seconds": 180,
        "admin_email": "",
        "smtp_server": "",
        "smtp_port": 587,
        "smtp_user": "",
        "smtp_password": str(),
    },
}


@dataclass
class SystemConfig:
    interface: Optional[str]
    csv_output_path: Optional[str] = None
    test_mode_output_path: Optional[str] = None
    log_file_path: Optional[str] = None


@dataclass
class ModelConfig:
    batch_size: int


@dataclass
class MitigationConfig:
    enable_blocking: bool
    block_duration_seconds: int
    admin_email: str
    smtp_server: str
    smtp_port: int
    smtp_user: str
    smtp_password: str


@dataclass
class AppConfig:
    system: SystemConfig
    model: ModelConfig
    mitigation: MitigationConfig


def validate_config(config: AppConfig) -> bool:
    # Dummy validation for essential fields
    if not config.system.interface or not config.mitigation.smtp_user:
        return False
    return True


def _generate_output_paths(system_conf: Dict[str, Any]) -> Dict[str, Any]:
    # 1. Handle CSV Outputs (Folder: cic_output)
    output_dir = BASE_DIR / "cic_output"
    output_dir.mkdir(exist_ok=True)

    if not system_conf.get("csv_output_path"):
        system_conf["csv_output_path"] = str(output_dir / "flow_logs.csv")
        logger.debug(f"Auto-set csv_output_path to {system_conf['csv_output_path']}")

    if not system_conf.get("test_mode_output_path"):
        system_conf["test_mode_output_path"] = str(output_dir / "test_results.csv")
        logger.debug(
            f"Auto-set test_mode_output_path to {system_conf['test_mode_output_path']}"
        )

    # 2. Handle Logs (Folder: logs)
    if not system_conf.get("log_file_path"):
        log_dir = BASE_DIR / "logs"
        log_dir.mkdir(exist_ok=True)
        system_conf["log_file_path"] = str(log_dir / "service.log")
        logger.debug(f"Auto-set log_file_path to {system_conf['log_file_path']}")

    return system_conf


def _load_env_variable(config_data: Dict[str, Any]) -> Dict[str, Any]:
    import os

    system = config_data.get("system", {})
    system["interface"] = os.getenv(
        "DDOS_MARTUMMAI_INTERFACE", system.get("interface", "")
    )

    model = config_data.get("model", {})
    model["batch_size"] = int(
        os.getenv("DDOS_MARTUMMAI_BATCH_SIZE", model.get("batch_size", 1000))
    )

    mitigation = config_data.get("mitigation", {})
    mitigation["smtp_server"] = os.getenv(
        "DDOS_MARTUMMAI_SMTP_SERVER", mitigation.get("smtp_server", "")
    )
    mitigation["smtp_port"] = int(
        os.getenv("DDOS_MARTUMMAI_SMTP_PORT", mitigation.get("smtp_port", 587))
    )
    mitigation["smtp_user"] = os.getenv(
        "DDOS_MARTUMMAI_SMTP_USER", mitigation.get("smtp_user", "")
    )
    mitigation["smtp_password"] = os.getenv(
        "DDOS_MARTUMMAI_SMTP_PASSWORD", mitigation.get("smtp_password", "")
    )
    mitigation["admin_email"] = os.getenv(
        "DDOS_MARTUMMAI_ADMIN_EMAIL", mitigation.get("admin_email", "")
    )

    env_blocking = os.getenv("DDOS_MARTUMMAI_ENABLE_BLOCKING")
    if env_blocking is not None:
        mitigation["enable_blocking"] = env_blocking.lower() == "true"
    else:
        mitigation["enable_blocking"] = mitigation.get("enable_blocking", False)

    mitigation["block_duration_seconds"] = int(
        os.getenv(
            "DDOS_MARTUMMAI_BLOCK_DURATION_SECONDS",
            mitigation.get("block_duration_seconds", 180),
        )
    )
    config_data["system"] = system
    config_data["model"] = model
    config_data["mitigation"] = mitigation
    return config_data


def load_config(path: str = None, override_env: bool = False) -> Optional[AppConfig]:
    # Determine config file path
    if path:
        config_file = Path(path)
    else:
        config_file = DEFAULT_CONFIG_PATH

    # --- Step 1: Ensure Config File Exists ---
    if not config_file.exists():
        logger.warning(f"Config file not found at {config_file}")

        # Try to copy from template
        if TEMPLATE_CONFIG_PATH.exists():
            logger.info(f"Creating default config from {TEMPLATE_CONFIG_PATH}...")
            try:
                config_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(TEMPLATE_CONFIG_PATH, config_file)
            except Exception as e:
                logger.error(f"Failed to copy template: {e}")

        # Fallback to internal default dict if template fails
        else:
            logger.warning(
                "Template not found! Generating config from internal defaults."
            )
            try:
                config_file.parent.mkdir(parents=True, exist_ok=True)
                with open(config_file, "w") as f:
                    yaml.dump(DEFAULT_CONFIG_DICT, f, default_flow_style=False)
            except Exception as e:
                logger.error(f"Could not create config file: {e}")
                return None

    # --- Step 2: Load and Process YAML ---
    try:
        with open(config_file, "r") as f:
            data = yaml.safe_load(f)

        # --- Step 3: Context-Aware Path Injection ---
        # If paths are defined in YAML, keep them.
        # If paths are None, generate local paths.
        data["system"] = _generate_output_paths(data.get("system", {}))

        # --- Step 4: Override config If environment variables exists ---
        if override_env:
            data = _load_env_variable(data)

        # --- Step 5: Return Typed Config ---
        return AppConfig(
            system=SystemConfig(**data["system"]),
            model=ModelConfig(**data["model"]),
            mitigation=MitigationConfig(**data["mitigation"]),
        )
    except Exception as e:
        logger.error(f"Failed to load config from {config_file}: {e}")
        import traceback

        traceback.print_exc()
        return None
