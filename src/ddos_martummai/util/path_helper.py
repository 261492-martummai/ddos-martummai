import sys
from pathlib import Path
from typing import Dict

APP_NAME = "ddos-martummai"


def get_app_paths() -> Dict[str, Path]:
    is_linux_prod = sys.platform == "linux" and Path(f"/opt/{APP_NAME}").exists()

    if is_linux_prod:
        # "mode": "production"
        base_dir = Path(f"/opt/{APP_NAME}")
        return {
            "base_dir": base_dir,
            "config_file": Path(f"/etc/{APP_NAME}/config.yml"),
            "token_file": Path(f"/etc/{APP_NAME}/google-drive-token.json"),
            "log_file": Path(f"/var/log/{APP_NAME}/service.log"),
            "data_dir": Path(f"/var/lib/{APP_NAME}"),
            "template_config": base_dir / "config" / "config.example.yml",
        }
    else:
        # "mode": "development"
        base_dir = Path(__file__).resolve().parent.parent.parent.parent
        return {
            "base_dir": base_dir,
            "config_file": base_dir / "config" / "config.yml",
            "token_file": base_dir / "google-drive-token.json",
            "log_file": base_dir / "logs" / "service.log",
            "data_dir": base_dir / "output",
            "template_config": base_dir / "config" / "config.example.yml",
        }
