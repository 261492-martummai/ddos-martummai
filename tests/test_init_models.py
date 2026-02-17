from ddos_martummai.init_models import (
    AppConfig,
    MitigationConfig,
    ModelConfig,
    SystemConfig,
)


def test_app_config_initialization_defaults_valid():
    config = AppConfig()
    assert isinstance(config.system, SystemConfig)
    assert isinstance(config.model, ModelConfig)
    assert isinstance(config.mitigation, MitigationConfig)
    assert config.model.batch_size == 1000


def test_mitigation_config_custom_values_valid():
    config = MitigationConfig(enable_blocking=True, block_duration_seconds=999)
    assert config.enable_blocking is True
    assert config.block_duration_seconds == 999
