import yaml
import os
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class SystemConfig:
    interface: Optional[str]
    csv_output_path: str
    test_mode_output: str

@dataclass
class ModelConfig:
    features: List[str]
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

# Default Template for regeneration
DEFAULT_CONFIG_DICT = {
    'system': {
        'interface': None,
        'csv_output_path': '/var/log/ddos-martummai/flow_logs.csv',
        'test_mode_output': '/tmp/ddos_martummai_test.csv'
    },
    'model': {
        # Note: Model paths are now internal to the package
        'batch_size': 1000
    },
    'mitigation': {
        'enable_blocking': False,
        'block_duration_seconds': 180,
        'admin_email': '',
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': 587,
        'smtp_user': '',
        'smtp_password': ''
    }
}

def validate_config(config: AppConfig) -> bool:
    if not config.system.interface:
        return False
    return True

def load_config(path: str) -> Optional[AppConfig]:
    if not os.path.exists(path):
        return None
    
    try:
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
            
        return AppConfig(
            system=SystemConfig(**data['system']),
            model=ModelConfig(**data['model']),
            mitigation=MitigationConfig(**data['mitigation'])
        )
    except Exception:
        return None