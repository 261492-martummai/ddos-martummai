from dataclasses import asdict, fields
from pathlib import Path

import pytest
import yaml

from ddos_martummai.init_models import AppConfig

# --- Configuration ---
ENV_PREFIX = "DDOS_MARTUMMAI_"

ROOT_DIR = Path(__file__).parent.parent


@pytest.fixture
def path_config_example_yaml():
    template_config_paths = ROOT_DIR / "config" / "config.example.yml"
    if not template_config_paths.exists():
        pytest.fail(f"Could not find config.example.yml in {template_config_paths}")
    return template_config_paths


@pytest.fixture
def path_env_example():
    env_path = ROOT_DIR / ".env.example"
    if not env_path.exists():
        pytest.fail(f"Could not find .env.example at {env_path}")
    return env_path


def test_yaml_structure_matches_app_config(path_config_example_yaml):
    app_config_data = asdict(AppConfig())

    with open(path_config_example_yaml, "r") as f:
        yaml_data = yaml.safe_load(f)

    assert set(app_config_data.keys()) == set(yaml_data.keys()), (
        f"Main sections mismatch.\nClass: {list(app_config_data.keys())}\nYAML: {list(yaml_data.keys())}"
    )

    for section in app_config_data:
        class_keys = set(app_config_data[section].keys())
        yaml_keys = set(yaml_data[section].keys())

        missing_in_yaml = class_keys - yaml_keys
        extra_in_yaml = yaml_keys - class_keys

        assert class_keys == yaml_keys, (
            f"\nSection '{section}' mismatch:\n"
            f"  - Missing in YAML: {missing_in_yaml}\n"
            f"  - Extra in YAML: {extra_in_yaml}"
        )


def test_env_example_matches_app_config_ignoring_paths(path_env_example):
    expected_envs = set()
    app_config = AppConfig()

    for field_main in fields(app_config):
        section_name = field_main.name
        sub_config = getattr(app_config, section_name)

        for field_sub in fields(sub_config):
            field_name = field_sub.name

            if field_name.endswith("_path"):
                continue

            env_var_name = f"{ENV_PREFIX}{field_name.upper()}"
            expected_envs.add(env_var_name)

    found_envs = set()
    with open(path_env_example, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if "=" in line:
                var_name = line.split("=", 1)[0].strip()
                if var_name.startswith(ENV_PREFIX):
                    found_envs.add(var_name)

    missing_in_file = expected_envs - found_envs

    assert not missing_in_file, (
        f"\n.env.example is missing variables required by AppConfig:\n"
        f"  - Missing in file (Need to add): {missing_in_file}\n"
        f"    (Extra variables in .env.example are allowed)"
    )
