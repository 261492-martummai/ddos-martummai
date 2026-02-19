from dataclasses import dataclass, field

from pydantic import BaseModel


@dataclass
class SystemConfig:
    interface: str = ""
    csv_output_path: str = ""
    test_mode_output_path: str = ""
    log_file_path: str = ""
    google_drive_upload: bool = False
    google_drive_folder_id: str = ""
    token_file_path: str = ""
    csv_rotation_rows: int = 1000000


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


# Monior
@dataclass
class FlowStats:
    start: int = 0
    packets: int = 0
    bytes: int = 0
    syn: int = 0
    ack: int = 0
    psh: int = 0
    rst: int = 0
    fin: int = 0


@dataclass
class TableRow:
    time: str
    src: str
    dst: str
    port: int
    packets: int
    bytes: int
    syn: int
    ack: int
    psh: int
    rst: int
    fin: int
    start: int
    duration: int


@dataclass
class LoginRequest(BaseModel):
    username: str
    password: str
