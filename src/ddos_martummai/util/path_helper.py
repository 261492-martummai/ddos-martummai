import sys
from pathlib import Path
from typing import Dict

APP_NAME = "ddos-martummai"


def get_app_paths() -> Dict[str, Path]:
    is_linux_prod = sys.platform == "linux" and Path(f"/etc/{APP_NAME}").exists()

    if is_linux_prod:
        base_dir = Path(f"/opt/{APP_NAME}")
        return {
            "mode": "production",
            "base_dir": base_dir,
            "config_file": Path(f"/etc/{APP_NAME}/config.yml"),
            "log_file": Path(f"/var/log/{APP_NAME}/service.log"),
            "data_dir": Path(f"/var/lib/{APP_NAME}"),
            "template_config": base_dir / "config" / "config.example.yml",
        }
    else:
        base_dir = Path(__file__).resolve().parent.parent.parent.parent
        return {
            "mode": "development",
            "base_dir": base_dir,
            "config_file": base_dir / "config" / "config.yml",
            "log_file": base_dir / "logs" / "service.log",
            "data_dir": base_dir / "cic_output",
            "template_config": base_dir / "config" / "config.example.yml",
        }
