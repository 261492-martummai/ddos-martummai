from dataclasses import dataclass, field


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
