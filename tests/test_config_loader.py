from dataclasses import asdict, fields
from unittest.mock import MagicMock, patch

import pytest
import yaml

from ddos_martummai.config_loader import DDoSConfigLoader
from ddos_martummai.init_models import (
    AppConfig,
    MitigationConfig,
    ModelConfig,
    SystemConfig,
)


@pytest.fixture
def mock_config_file(tmp_path):
    config = tmp_path / "config.yml"
    return config


@pytest.fixture
def mock_template_path(tmp_path):
    tpl = tmp_path / "config.template.yml"
    tpl.touch()
    return tpl


@pytest.fixture
def mock_app_config():
    return AppConfig(
        system=SystemConfig(
            interface="eth0",
            csv_output_path="/tmp/test.csv",
            test_mode_output_path="/tmp/test_result.csv",
            log_file_path="/tmp/test.log",
            google_drive_upload=True,
            google_drive_folder_id="folder123",
            token_file_path="/tmp/token.json",
            csv_rotation_rows=500000,
        ),
        model=ModelConfig(batch_size=1000),
        mitigation=MitigationConfig(
            enable_blocking=True,
            block_duration_seconds=60,
            admin_email="admin@test.com",
            smtp_server="smtp.test.com",
            smtp_user="user",
            smtp_password="password",
        ),
    )


def test_ensure_config_file_exists_when_file_exists(mock_config_file):
    mock_config_file.touch()
    with (
        patch("ddos_martummai.config_loader.shutil.copy") as mock_copy,
        patch("ddos_martummai.config_loader.YAML.dump") as mock_dump,
    ):
        loader = DDoSConfigLoader(mock_config_file)
        loader._ensure_config_file_exists()

        mock_copy.assert_not_called()
        mock_dump.assert_not_called()


def test_build_config_file_when_main_config_missing(
    mock_config_file, mock_template_path
):
    with patch.dict(
        "ddos_martummai.config_loader.APP_PATHS",
        {"template_config": mock_template_path},
    ):
        with patch("ddos_martummai.config_loader.shutil.copy") as mock_copy:
            loader = DDoSConfigLoader(mock_config_file)
            loader._ensure_config_file_exists()

            mock_copy.assert_called_once_with(mock_template_path, mock_config_file)


def test_build_config_file_when_main_config_and_template_file_missing(mock_config_file):
    mock_template_path = MagicMock()
    mock_template_path.exists.return_value = False

    with patch.dict(
        "ddos_martummai.config_loader.APP_PATHS",
        {"template_config": mock_template_path},
    ):
        loader = DDoSConfigLoader(mock_config_file)
        loader._ensure_config_file_exists()

        assert mock_config_file.exists()
        with open(mock_config_file, "r") as f:
            data = yaml.safe_load(f)

            assert "system" in data
            assert "model" in data
            assert "mitigation" in data


def test_load_valid_app_config(mock_config_file, mock_app_config):
    with open(mock_config_file, "w") as f:
        yaml.dump(asdict(mock_app_config), f)

    loader = DDoSConfigLoader(mock_config_file)
    loader._load_app_config()

    assert loader.app_config == mock_app_config


def test_inject_system_paths_when_config_empty(mock_config_file, tmp_path):
    with open(mock_config_file, "w") as f:
        yaml.dump(asdict(AppConfig()), f)

    # Mock APP_PATHS
    data_dir = tmp_path / "data"
    log_file = tmp_path / "logs" / "app.log"

    with patch.dict(
        "ddos_martummai.config_loader.APP_PATHS",
        {"data_dir": data_dir, "log_file": log_file},
    ):
        loader = DDoSConfigLoader(mock_config_file)
        loader._load_app_config()
        loader._inject_system_paths()

        assert data_dir.exists()
        assert log_file.parent.exists()

        assert loader.app_config.system.csv_output_path == str(data_dir)
        assert loader.app_config.system.test_mode_output_path == str(
            data_dir / "test_results.csv"
        )
        assert loader.app_config.system.log_file_path == str(log_file)


def test_inject_system_paths_when_config_exist(mock_config_file, tmp_path):
    data = AppConfig()
    data.system.csv_output_path = "/custom/data.csv"
    data.system.test_mode_output_path = "/custom/test.csv"
    data.system.log_file_path = "/custom/app.log"
    data.system.token_file_path = "/custom/token.json"
    data.system.google_drive_folder_id = "abcdefg111"

    data_dir = tmp_path / "data"
    log_file = tmp_path / "logs" / "app.log"

    with open(mock_config_file, "w") as f:
        yaml.dump(asdict(data), f)

    loader = DDoSConfigLoader(mock_config_file)
    loader._load_app_config()
    with patch.dict(
        "ddos_martummai.config_loader.APP_PATHS",
        {"data_dir": data_dir, "log_file": log_file},
    ):
        loader._inject_system_paths()

    assert loader.app_config == data


def test_env_override_disabled(mock_config_file, mock_app_config, monkeypatch):
    loader = DDoSConfigLoader(mock_config_file, override_env=False)
    loader.app_config = mock_app_config

    prefix = "DDOS_MARTUMMAI_"
    target_configs = [
        loader.app_config.system,
        loader.app_config.model,
        loader.app_config.mitigation,
    ]

    for config in target_configs:
        for env_field in fields(config):
            env_key = f"{prefix}{env_field.name.upper()}"
            monkeypatch.setenv(env_key, "hacked")

    loader._check_override_env()

    assert loader.app_config == mock_app_config


def test_override_enabled_success(mock_config_file, mock_app_config, monkeypatch):
    loader = DDoSConfigLoader(mock_config_file, override_env=True)
    loader.app_config = mock_app_config

    # Set Init values
    loader.app_config.system.interface = "eth0"
    loader.app_config.model.batch_size = 100
    loader.app_config.mitigation.enable_blocking = False

    # Set Env Vars
    monkeypatch.setenv("DDOS_MARTUMMAI_INTERFACE", "eth1")
    monkeypatch.setenv("DDOS_MARTUMMAI_BATCH_SIZE", "999")
    monkeypatch.setenv("DDOS_MARTUMMAI_ENABLE_BLOCKING", "true")

    loader._check_override_env()

    assert loader.app_config.system.interface == "eth1"
    assert loader.app_config.model.batch_size == 999
    assert loader.app_config.mitigation.enable_blocking is True


def test_override_invalid_type(mock_config_file, mock_app_config, monkeypatch):
    loader = DDoSConfigLoader(mock_config_file, override_env=True)
    loader.app_config = mock_app_config
    loader.app_config.model.batch_size = 50

    monkeypatch.setenv("DDOS_MARTUMMAI_BATCH_SIZE", "number")

    with patch("ddos_martummai.config_loader.logger") as mock_logger:
        loader._check_override_env()

        assert loader.app_config.model.batch_size == 50
        mock_logger.error.assert_called()


def test_fail_validation_in_headless(mock_config_file, mock_app_config):
    loader = DDoSConfigLoader(mock_config_file)
    loader.app_config = mock_app_config
    loader.app_config.system.interface = ""
    loader.app_config.mitigation.admin_email = ""

    with (
        patch("sys.stdin.isatty", return_value=False),
        patch("ddos_martummai.config_loader.logger"),
    ):
        with pytest.raises(SystemExit) as exc:
            loader._validate_config()

        assert exc.value.code == 1


def test_interactive_wizard_success(mock_config_file, mock_app_config):
    loader = DDoSConfigLoader(mock_config_file)
    loader.app_config = mock_app_config
    loader.app_config.system.interface = ""
    loader.app_config.mitigation.smtp_user = ""
    loader.app_config.mitigation.smtp_password = ""

    with (
        patch("sys.stdin.isatty", return_value=True),
        patch("ddos_martummai.config_loader.SetupWizard") as MockWizard,
    ):
        # Mock Wizard returns True (Success)
        MockWizard.return_value.run.return_value = True

        loader._validate_config()

        MockWizard.assert_called_once()


def test_interactive_wizard_cancelled(mock_config_file, mock_app_config):
    loader = DDoSConfigLoader(mock_config_file)
    loader.app_config = mock_app_config
    loader.app_config.system.interface = ""

    with (
        patch("sys.stdin.isatty", return_value=True),
        patch("ddos_martummai.config_loader.SetupWizard") as MockWizard,
    ):
        # Mock Wizard returns False (User cancelled)
        MockWizard.return_value.run.return_value = False

        with pytest.raises(SystemExit) as exc:
            loader._validate_config()

        assert exc.value.code == 1


def test_config_loader_successful_full_flow(tmp_path, monkeypatch):
    """
    Validates the complete configuration loading workflow.

    Scenario:
    1. A basic config file exists (missing some paths, contains old values).
    2. Environment variables are set (to test the override feature).
    3. The system must:
       - Load the file.
       - Calculate/Inject missing paths.
       - Override values using Env vars.
       - Setup the logger correctly.
    """

    # --- 1. ARRANGE ---

    # 1.1 Prepare mock paths using tmp_path
    mock_config_file = tmp_path / "config.yml"
    mock_data_dir = tmp_path / "output"
    mock_log_file = tmp_path / "logs" / "system.log"
    mock_test_mode_output_path = tmp_path / "output" / "test_results.csv"
    mock_token_file = tmp_path / "token.json"

    # 1.2 Prepare the initial YAML file
    # Note:
    # - 'batch_size' is set to 100 (Expected to be overridden to 9999 by Env).
    # - 'log_file_path' is omitted (System should auto-inject this from APP_PATHS).
    initial_yaml_data = {
        "system": {"interface": "eth0"},
        "model": {"batch_size": 100},
        "mitigation": {
            "enable_blocking": False,
            "admin_email": "admin@test.com",
            "smtp_user": "test_user",
            "smtp_password": "test_password",
        },
    }
    with open(mock_config_file, "w") as f:
        yaml.dump(initial_yaml_data, f)

    # 1.3 Set Environment Variables (Simulate value overrides)
    monkeypatch.setenv("DDOS_MARTUMMAI_BATCH_SIZE", "9999")
    monkeypatch.setenv("DDOS_MARTUMMAI_ENABLE_BLOCKING", "true")

    # --- 2. ACT ---

    with (
        patch.dict(
            "ddos_martummai.config_loader.APP_PATHS",
            {
                "data_dir": mock_data_dir,
                "log_file": mock_log_file,
                "test_mode_output_path": mock_test_mode_output_path,
                "token_file": mock_token_file,
            },
        ),
    ):
        # Initialize loader with environment override enabled
        loader = DDoSConfigLoader(mock_config_file, override_env=True)

        # Execute the main loading process
        config = loader.load()

        # --- 3. ASSERT ---

        # 3.1 Verify that static values from the file are loaded correctly
        assert config.system.interface == "eth0"
        assert config.mitigation.admin_email == "admin@test.com"

        # 3.2 Verify that Environment Variables correctly overrode the file values
        assert config.model.batch_size == 9999  # Changed from 100 -> 9999
        assert config.mitigation.enable_blocking is True  # Changed from False -> True

        # 3.3 Verify that Path Injection logic works correctly
        # The system should auto-populate paths based on the injected 'data_dir'
        expected_csv_path = str(mock_data_dir)
        expected_test_mode_path = str(mock_test_mode_output_path)
        expected_log_path = str(mock_log_file)
        expected_token_path = str(mock_token_file)
        assert config.system.csv_output_path == expected_csv_path
        assert config.system.test_mode_output_path == expected_test_mode_path
        assert config.system.log_file_path == expected_log_path
        assert config.system.token_file_path == expected_token_path

        # Verify that actual directories were created
        assert mock_data_dir.exists()
        assert mock_log_file.parent.exists()

        # 3.4 Verify internal state consistency
        assert loader.config_file == mock_config_file
