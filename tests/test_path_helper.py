from unittest.mock import patch

from ddos_martummai.util.path_helper import get_app_paths


def test_get_app_paths_linux_prod_returns_prod_paths():
    with (
        patch("sys.platform", "linux"),
        patch("pathlib.Path.exists", return_value=True),
    ):
        paths = get_app_paths()
        assert str(paths["base_dir"]) == "/opt/ddos-martummai"
        assert str(paths["config_file"]) == "/etc/ddos-martummai/config.yml"


def test_get_app_paths_dev_mode_returns_local_paths():
    with patch("sys.platform", "win32"):
        paths = get_app_paths()
        assert "opt" not in str(paths["base_dir"])
        assert "config.yml" in str(paths["config_file"])
