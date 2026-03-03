from dataclasses import dataclass, field

from pydantic import BaseModel


@dataclass
class SystemConfig:
    interface: str = ""
    google_drive_upload: bool = False
    google_drive_folder_id: str = ""
    csv_rotation_rows: int = 1000000
    csv_output_path: str = ""
    test_mode_output_path: str = ""
    log_file_path: str = ""
    token_file_path: str = ""


@dataclass
class ModelConfig:
    batch_size: int = 1000


@dataclass
class MitigationConfig:
    enable_blocking: bool = False
    block_duration_seconds: int = 180
    enable_email_alert: bool = False
    admin_email: str = ""
    smtp_server: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    alert_cooldown_seconds: int = 300


@dataclass
class DetectorConfig:
    # Case 4: Global Botnet
    global_min_samples: int = 50
    global_attack_ratio: float = 0.75
    global_ip_diversity: float = 0.40

    # Case 3: Slow/Persistent Attack
    slow_min_duration: int = 300
    slow_max_pps: float = 0.50
    slow_attack_ratio: float = 0.40

    # Case 1: Batch Volumetric (Burst)
    ip_burst_threshold: float = 0.70
    ip_min_count_in_batch: int = 15

    # Memory Management
    mem_timeout: int = 900
    cleanup_interval: int = 600


@dataclass
class AppConfig:
    system: SystemConfig = field(default_factory=SystemConfig)
    model: ModelConfig = field(default_factory=ModelConfig)
    mitigation: MitigationConfig = field(default_factory=MitigationConfig)
    detector: DetectorConfig = field(default_factory=DetectorConfig)


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
