import os
from pathlib import Path
from unittest.mock import patch

from ddos_martummai.util.path_helper import get_app_paths


def test_get_app_paths_linux_prod_returns_prod_paths():
    with (
        patch("sys.platform", "linux"),
        patch.dict(os.environ, {"APP_ENV": "production"}),
    ):
        paths = get_app_paths()
        assert paths["base_dir"] == Path("/opt/ddos-martummai")
        assert paths["config_file"] == Path("/etc/ddos-martummai/config.yml")


def test_get_app_paths_dev_mode_returns_local_paths():
    with patch("sys.platform", "win32"):
        paths = get_app_paths()
        assert "opt" not in str(paths["base_dir"])
        assert "config.yml" in str(paths["config_file"])


def test_get_app_paths_linux_non_prod_returns_local_paths():
    with (
        patch("sys.platform", "linux"),
        patch.dict(os.environ, {}, clear=True),
    ):
        paths = get_app_paths()
        assert "opt" not in str(paths["base_dir"])
        assert "config.yml" in str(paths["config_file"])
