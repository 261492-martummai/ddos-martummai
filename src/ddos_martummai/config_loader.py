import logging
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import yaml

logger = logging.getLogger("ddos-martummai")

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DEFAULT_CONFIG_PATH = BASE_DIR / "config/config.yml"
TEMPLATE_CONFIG_PATH = BASE_DIR / "config/config.example.yml"

# =========================
# Dataclasses with defaults
# =========================


@dataclass
class SystemConfig:
    interface: str = ""
    csv_output_path: str = ""
    test_mode_output_path: str = ""
    log_file_path: str = ""


@dataclass
class ModelConfig:
    batch_size: int = 1000


@dataclass
class MitigationConfig:
    enable_blocking: bool = False
    block_duration_seconds: int = 180
    admin_email: str = ""
    smtp_server: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""


@dataclass
class AppConfig:
    system: SystemConfig = field(default_factory=SystemConfig)
    model: ModelConfig = field(default_factory=ModelConfig)
    mitigation: MitigationConfig = field(default_factory=MitigationConfig)


# =========================
# Helpers
# =========================


def ensure_file_exists(config_file: Path):
    if config_file.exists():
        return

    logger.warning(f"Config not found: {config_file}")

    config_file.parent.mkdir(parents=True, exist_ok=True)

    if TEMPLATE_CONFIG_PATH.exists():
        logger.info("Copying from template...")
        shutil.copy(TEMPLATE_CONFIG_PATH, config_file)
    else:
        logger.info("Creating from internal defaults...")
        with open(config_file, "w") as f:
            yaml.dump(AppConfig(), f)


def inject_paths(system: SystemConfig) -> SystemConfig:
    output_dir = BASE_DIR / "cic_output"
    log_dir = BASE_DIR / "logs"
    output_dir.mkdir(exist_ok=True)
    log_dir.mkdir(exist_ok=True)

    if not system.csv_output_path:
        system.csv_output_path = str(output_dir / "flow_logs.csv")

    if not system.test_mode_output_path:
        system.test_mode_output_path = str(output_dir / "test_results.csv")

    if not system.log_file_path:
        system.log_file_path = str(log_dir / "service.log")

    return system


def override_from_env(config: AppConfig) -> AppConfig:
    s = config.system
    m = config.model
    mit = config.mitigation

    s.interface = os.getenv("DDOS_MARTUMMAI_INTERFACE", s.interface)

    m.batch_size = int(os.getenv("DDOS_MARTUMMAI_BATCH_SIZE", m.batch_size))

    mit.smtp_server = os.getenv("DDOS_MARTUMMAI_SMTP_SERVER", mit.smtp_server)
    mit.smtp_port = int(os.getenv("DDOS_MARTUMMAI_SMTP_PORT", mit.smtp_port))
    mit.smtp_user = os.getenv("DDOS_MARTUMMAI_SMTP_USER", mit.smtp_user)
    mit.smtp_password = os.getenv("DDOS_MARTUMMAI_SMTP_PASSWORD", mit.smtp_password)
    mit.admin_email = os.getenv("DDOS_MARTUMMAI_ADMIN_EMAIL", mit.admin_email)

    env_blocking = os.getenv("DDOS_MARTUMMAI_ENABLE_BLOCKING")
    if env_blocking is not None:
        mit.enable_blocking = env_blocking.lower() == "true"

    mit.block_duration_seconds = int(
        os.getenv("DDOS_MARTUMMAI_BLOCK_DURATION_SECONDS", mit.block_duration_seconds)
    )

    return config


def validate_config(config: AppConfig):
    errors = []

    if not config.system.interface:
        errors.append("system.interface is required")

    if config.mitigation.enable_blocking:
        if not config.mitigation.smtp_user:
            errors.append("smtp_user required when blocking enabled")
        if not config.mitigation.admin_email:
            errors.append("admin_email required when blocking enabled")

    if errors:
        raise ValueError("Invalid config:\n" + "\n".join(errors))


# =========================
# Main loader
# =========================


def load_config(
    path: Optional[str] = None,
    override_env_vars: bool = False,
) -> AppConfig:
    config_file = Path(path) if path else DEFAULT_CONFIG_PATH

    ensure_file_exists(config_file)

    with open(config_file) as f:
        raw = yaml.safe_load(f) or {}

    config = AppConfig(
        system=SystemConfig(**raw.get("system", {})),
        model=ModelConfig(**raw.get("model", {})),
        mitigation=MitigationConfig(**raw.get("mitigation", {})),
    )

    config.system = inject_paths(config.system)

    if override_env_vars:
        config = override_from_env(config)

    validate_config(config)
    return config
