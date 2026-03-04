import logging
from email.mime.text import MIMEText
from multiprocessing import Queue
from unittest.mock import MagicMock, patch

import pytest

from ddos_martummai.init_models import AppConfig, MitigationConfig, SystemConfig
from ddos_martummai.mitigator import (
    INVALID_IP,
    IPSET_NAME,
    IPSET_PATH,
    IPTABLES_PATH,
    Mitigator,
)

# ==========================================
# FIXTURES
# ==========================================


@pytest.fixture
def mock_app_config():
    return AppConfig(
        system=SystemConfig(interface="eth0"),
        mitigation=MitigationConfig(
            enable_email_alert=True,
            enable_blocking=True,
            block_duration_seconds=60,
            alert_cooldown_seconds=300,
            admin_email="admin@test.com",
            smtp_user="sender@test.com",
            smtp_password="password123",
            smtp_server="smtp.test.com",
            smtp_port=587,
        ),
    )


@pytest.fixture
def mock_mitigation_event_queue():
    return Queue()


@pytest.fixture
def mitigator(mock_app_config, mock_mitigation_event_queue):
    with patch("ddos_martummai.mitigator.subprocess.run"):
        return Mitigator(mock_app_config, mock_mitigation_event_queue)


# ==========================================
# INFRASTRUCTURE TESTS (IPSET & IPTABLES)
# ==========================================


def test_setup_infrastructure_success(mitigator):
    with patch("ddos_martummai.mitigator.subprocess.run") as mock_run:
        # Simulate successful creation of ipset and iptables rule
        mock_run.side_effect = [
            MagicMock(returncode=0),  # ipset create
            MagicMock(returncode=1),  # iptables -C (rule not found)
            MagicMock(returncode=0),  # iptables -I (rule created successfully)
        ]

        mitigator._setup_infrastructure()

        assert mock_run.call_count == 3
        # check iptables -I
        mock_run.assert_called_with(
            [
                IPTABLES_PATH,
                "-I",
                "INPUT",
                "-m",
                "set",
                "--match-set",
                IPSET_NAME,
                "src",
                "-j",
                "DROP",
            ],
            check=True,
        )


def test_setup_infrastructure_rule_already_exists(mitigator):
    with patch("ddos_martummai.mitigator.subprocess.run") as mock_run:
        # Simulate successful creation of ipset and iptables rule already exists
        mock_run.side_effect = [
            MagicMock(returncode=0),  # ipset create
            MagicMock(returncode=0),  # iptables -C (rule already exists)
        ]

        mitigator._setup_infrastructure()

        assert mock_run.call_count == 2  # Should stop after checking, not proceed to -I


def test_setup_infrastructure_file_not_found(mitigator):
    with patch(
        "ddos_martummai.mitigator.subprocess.run", side_effect=FileNotFoundError
    ):
        with pytest.raises(FileNotFoundError):
            mitigator._setup_infrastructure()


# ==========================================
# BLOCK IP TESTS (IPSET)
# ==========================================


def test_block_ip_success(mitigator):
    with (
        patch.object(mitigator, "_valid_ip", return_value=True),
        patch("ddos_martummai.mitigator.subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=0)

        result = mitigator.block_ip("8.8.8.8")

        assert result is True
        mock_run.assert_called_once_with(
            [IPSET_PATH, "add", IPSET_NAME, "8.8.8.8", "timeout", "60"],
            capture_output=True,
            text=True,
            check=False,
        )


def test_block_ip_already_blocked(mitigator, caplog):
    caplog.set_level(logging.DEBUG)
    with (
        patch.object(mitigator, "_valid_ip", return_value=True),
        patch("ddos_martummai.mitigator.subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(
            returncode=1,
            stderr="ipset v7.15: Element cannot be added to the set: it's already added",
        )

        result = mitigator.block_ip("8.8.8.8")

        assert result is False
        assert "is already blocked" in caplog.text


def test_block_ip_other_error(mitigator, caplog):
    with (
        patch.object(mitigator, "_valid_ip", return_value=True),
        patch("ddos_martummai.mitigator.subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=1, stderr="Some unknown error")

        result = mitigator.block_ip("8.8.8.8")

        assert result is False
        assert "Failed to add IP to ipset: Some unknown error" in caplog.text


def test_block_ip_exception(mitigator, caplog):
    with (
        patch.object(mitigator, "_valid_ip", return_value=True),
        patch(
            "ddos_martummai.mitigator.subprocess.run",
            side_effect=Exception("System Crash"),
        ),
    ):
        result = mitigator.block_ip("8.8.8.8")

        assert result is False
        assert "Error modifying ipset: System Crash" in caplog.text


def test_block_ip_disabled_or_invalid(mitigator):
    # Disable blocking
    mitigator.config.mitigation.enable_blocking = False
    assert mitigator.block_ip("8.8.8.8") is False

    # Enable blocking but IP is invalid
    mitigator.config.mitigation.enable_blocking = True
    with patch.object(mitigator, "_valid_ip", return_value=False):
        assert mitigator.block_ip("192.168.1.50") is False


# ==========================================
# EMAIL ALERT & COOLDOWN TESTS
# ==========================================


def test_filter_ips_for_alert_cooldown_logic(mitigator):
    ip1, ip2 = "1.1.1.1", "2.2.2.2"

    with patch.object(mitigator, "_valid_ip", return_value=True):
        # Successful alert for both IPs (initially empty cache)
        with patch("ddos_martummai.mitigator.time.time", return_value=1000.0):
            filtered = mitigator._filter_ips_for_alert([ip1, ip2])
            assert ip1 in filtered
            assert ip2 in filtered
            assert mitigator.alert_cache[ip1] == 1000.0

        # Pass 100 seconds, still within cooldown
        with patch("ddos_martummai.mitigator.time.time", return_value=1100.0):
            filtered = mitigator._filter_ips_for_alert([ip1])
            assert ip1 not in filtered  # Filtered out

        # Pass 400 seconds, cooldown expired
        with patch("ddos_martummai.mitigator.time.time", return_value=1400.0):
            filtered = mitigator._filter_ips_for_alert([ip1])
            assert ip1 in filtered  # Can send again
            assert mitigator.alert_cache[ip1] == 1400.0  # Updated last alert time


def test_send_alert_filtered_out(mitigator):
    # Test case where all IPs are filtered out, no email should be sent
    with (
        patch.object(mitigator, "_filter_ips_for_alert", return_value=[]),
        patch.object(mitigator, "_create_alert_message") as mock_create,
    ):
        mitigator.send_alert("1.1.1.1", "Flow Info")
        mock_create.assert_not_called()


def test_send_alert_success(mitigator):
    with (
        patch.object(mitigator, "_filter_ips_for_alert", return_value=["1.1.1.1"]),
        patch.object(mitigator, "_create_alert_message") as mock_create,
        patch.object(mitigator, "_send_email_async") as mock_send,
    ):
        mock_msg = MIMEText("Dummy")
        mock_create.return_value = mock_msg

        mitigator.send_alert("1.1.1.1", "Flow Info")

        mock_create.assert_called_once_with("1.1.1.1", "Flow Info")
        mock_send.assert_called_once_with(mock_msg)


def test_send_alert_disabled(mitigator, mock_app_config):
    mock_app_config.mitigation.enable_email_alert = False
    with patch.object(mitigator, "_filter_ips_for_alert") as mock_filter:
        mitigator.send_alert("1.1.1.1", "info")
        mock_filter.assert_not_called()


# ==========================================
# STANDARD EMAIL CONFIG TESTS (UNCHANGED)
# ==========================================


def test_email_alert_enabled(mitigator, mock_app_config):
    assert mitigator._email_alert_enabled() is True
    mock_app_config.mitigation.enable_email_alert = False
    assert mitigator._email_alert_enabled() is False


def test_create_smtp_connection(mitigator):
    with patch("ddos_martummai.mitigator.smtplib.SMTP") as mock_smtp_class:
        mock_server = MagicMock()
        mock_smtp_class.return_value = mock_server

        server = mitigator._create_smtp_connection()

        mock_smtp_class.assert_called_once_with("smtp.test.com", 587, timeout=5)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("sender@test.com", "password123")
        assert server == mock_server


def test_validate_smtp_config_success(mitigator):
    with (
        patch.object(mitigator, "_create_smtp_connection") as mock_create_conn,
        patch("ddos_martummai.mitigator.logger.info") as mock_logger,
    ):
        mitigator._validate_smtp_config()
        mock_create_conn.assert_called_once()
        mock_logger.assert_called_with("SMTP configuration validated successfully.")


def test_validate_smtp_config_failure(mitigator, caplog):
    with (
        patch.object(
            mitigator,
            "_create_smtp_connection",
            side_effect=Exception("Connection Refused"),
        ),
        patch.object(mitigator, "_email_alert_enabled", return_value=True),
    ):
        mitigator._validate_smtp_config()
        assert "SMTP validation failed: Connection Refused" in caplog.text


def test_create_alert_message(mitigator):
    ip = "192.168.1.100"
    flow_info = "Packets: 10000"
    msg = mitigator._create_alert_message(ip, flow_info)

    assert isinstance(msg, MIMEText)
    assert msg["Subject"] == f"ALERT: DDoS Attack Detected - {ip}"
    assert msg["From"] == "sender@test.com"
    assert msg["To"] == "admin@test.com"
    assert ip in msg.get_payload()


def test_send_email_async(mitigator):
    msg = MIMEText("test")
    with (
        patch("ddos_martummai.mitigator.threading.Thread") as mock_thread_class,
        patch.object(mitigator, "_create_smtp_connection") as mock_create_conn,
    ):
        mitigator._send_email_async(msg)
        mock_thread_class.assert_called_once()
        thread_target_func = mock_thread_class.call_args[1]["target"]

        mock_server = MagicMock()
        mock_create_conn.return_value.__enter__.return_value = mock_server
        thread_target_func()
        mock_server.send_message.assert_called_once_with(msg)


def test_send_email_async_exception(mitigator, caplog):
    msg = MIMEText("test")
    with (
        patch("ddos_martummai.mitigator.threading.Thread") as mock_thread_class,
        patch.object(
            mitigator, "_create_smtp_connection", side_effect=Exception("Network Down")
        ),
    ):
        mitigator._send_email_async(msg)
        thread_target_func = mock_thread_class.call_args[1]["target"]
        thread_target_func()
        assert "Failed to send email: Network Down" in caplog.text


# ==========================================
# IP VALIDATION TESTS (UNCHANGED)
# ==========================================


def test_valid_ip_invalid_format(mitigator):
    assert mitigator._valid_ip(None) is False
    assert mitigator._valid_ip("") is False
    assert mitigator._valid_ip(INVALID_IP) is False


def test_valid_ip_matches_system_interface(mitigator):
    with patch("ddos_martummai.mitigator.psutil.net_if_addrs") as mock_net_addrs:
        mock_snic = MagicMock()
        mock_snic.address = "192.168.1.50"
        mock_net_addrs.return_value = {"eth0": [mock_snic]}
        assert mitigator._valid_ip("192.168.1.50") is False


def test_valid_ip_is_external(mitigator):
    with patch("ddos_martummai.mitigator.psutil.net_if_addrs") as mock_net_addrs:
        mock_snic = MagicMock()
        mock_snic.address = "192.168.1.50"
        mock_net_addrs.return_value = {"eth0": [mock_snic]}
        assert mitigator._valid_ip("8.8.8.8") is True


def test_valid_ip_psutil_exception(mitigator, caplog):
    with patch(
        "ddos_martummai.mitigator.psutil.net_if_addrs",
        side_effect=Exception("OS Error"),
    ):
        assert mitigator._valid_ip("8.8.8.8") is True
        assert "Error checking interface IPs: OS Error" in caplog.text
