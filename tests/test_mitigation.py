import subprocess
from email.mime.text import MIMEText
from unittest.mock import MagicMock, patch

import pytest

from ddos_martummai.init_models import AppConfig, MitigationConfig, SystemConfig
from ddos_martummai.mitigator import (
    INVALID_IP,
    IPTABLES_PATH,
    Mitigator,
)

# FIXTURES


@pytest.fixture
def mock_app_config():
    return AppConfig(
        system=SystemConfig(interface="eth0"),
        mitigation=MitigationConfig(
            enable_email_alert=True,
            enable_blocking=True,
            block_duration_seconds=60,
            admin_email="admin@test.com",
            smtp_user="sender@test.com",
            smtp_password="password123",
            smtp_server="smtp.test.com",
            smtp_port=587,
        ),
    )


@pytest.fixture
def mitigator(mock_app_config):
    return Mitigator(mock_app_config)


# EMAIL & SMTP TESTS


def test_email_alert_enabled(mitigator, mock_app_config):
    # Case 1: Enabled
    assert mitigator._email_alert_enabled() is True

    # Case 2: Disabled
    mock_app_config.mitigation.enable_email_alert = False
    assert mitigator._email_alert_enabled() is False


def test_create_smtp_connection(mitigator):
    # Simulate smtplib.SMTP()
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


def test_validate_smtp_config_when_email_disabled(mitigator, caplog):
    mitigator.config.mitigation.enable_email_alert = False

    mitigator._validate_smtp_config()
    assert "Email alerting is disabled: missing config." in caplog.text


def test_create_alert_message(mitigator):
    ip = "192.168.1.100"
    flow_info = "Packets: 10000"

    msg = mitigator._create_alert_message(ip, flow_info)

    assert isinstance(msg, MIMEText)
    assert msg["Subject"] == f"ALERT: DDoS Attack Detected - {ip}"
    assert msg["From"] == "sender@test.com"
    assert msg["To"] == "admin@test.com"
    assert ip in msg.get_payload()
    assert flow_info in msg.get_payload()


def test_send_alert_enabled(mitigator):
    with (
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

    with patch.object(mitigator, "_create_alert_message") as mock_create:
        mitigator.send_alert("1.1.1.1", "info")

        mock_create.assert_not_called()


def test_send_email_async(mitigator):
    msg = MIMEText("test")

    with (
        patch("ddos_martummai.mitigator.threading.Thread") as mock_thread_class,
        patch.object(mitigator, "_create_smtp_connection") as mock_create_conn,
    ):
        mitigator._send_email_async(msg)

        # Check that a Thread was created to send the email
        mock_thread_class.assert_called_once()
        mock_thread_class.return_value.start.assert_called_once()

        # Extract the target function of the thread to run it manually
        thread_target_func = mock_thread_class.call_args[1]["target"]

        # Simulate a successful SMTP connection
        mock_server = MagicMock()
        mock_create_conn.return_value.__enter__.return_value = mock_server

        # Simulate running the Thread
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


# IP VALIDATION TESTS


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


# IPTABLES (MITIGATION) TESTS


def test_iptables_rule_exists_true(mitigator):
    with patch("ddos_martummai.mitigator.subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0

        assert mitigator._iptables_rule_exists("1.1.1.1") is True


def test_iptables_rule_exists_false(mitigator):
    with patch("ddos_martummai.mitigator.subprocess.run") as mock_run:
        mock_run.return_value.returncode = 1

        assert mitigator._iptables_rule_exists("1.1.1.1") is False


def test_iptables_rule_exists_not_found(mitigator):
    with patch(
        "ddos_martummai.mitigator.subprocess.run", side_effect=FileNotFoundError
    ):
        with pytest.raises(FileNotFoundError):
            mitigator._iptables_rule_exists("1.1.1.1")


def test_iptables_add_rule_success(mitigator):
    with patch("ddos_martummai.mitigator.subprocess.run") as mock_run:
        mitigator._iptables_add_rule("1.1.1.1")

        mock_run.assert_called_once_with(
            [IPTABLES_PATH, "-A", "INPUT", "-s", "1.1.1.1", "-j", "DROP"], check=True
        )


def test_iptables_add_rule_failure(mitigator):
    with patch(
        "ddos_martummai.mitigator.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "cmd"),
    ):
        with pytest.raises(subprocess.CalledProcessError):
            mitigator._iptables_add_rule("1.1.1.1")


def test_block_ip_success(mitigator):
    with (
        patch.object(mitigator, "_valid_ip", return_value=True) as mock_valid,
        patch.object(
            mitigator, "_iptables_rule_exists", return_value=False
        ) as mock_exists,
        patch.object(mitigator, "_iptables_add_rule") as mock_add,
        patch.object(mitigator, "_schedule_unblock") as mock_schedule,
    ):
        mitigator.block_ip("8.8.8.8")

        mock_valid.assert_called_once_with("8.8.8.8")
        mock_exists.assert_called_once_with("8.8.8.8")
        mock_add.assert_called_once_with("8.8.8.8")
        mock_schedule.assert_called_once_with("8.8.8.8")


def test_block_ip_already_blocked(mitigator):
    with (
        patch.object(mitigator, "_valid_ip", return_value=True) as mock_valid,
        patch.object(
            mitigator, "_iptables_rule_exists", return_value=True
        ) as mock_exists,
        patch.object(mitigator, "_iptables_add_rule") as mock_add,
    ):
        mitigator.block_ip("8.8.8.8")

        mock_valid.assert_called_once_with("8.8.8.8")
        mock_exists.assert_called_once_with("8.8.8.8")
        mock_add.assert_not_called()


def test_block_ip_exception_handled_silently(mitigator):
    with (
        patch.object(mitigator, "_valid_ip", return_value=True),
        patch.object(mitigator, "_iptables_rule_exists", side_effect=FileNotFoundError),
    ):
        try:
            mitigator.block_ip("8.8.8.8")
        except Exception:
            pytest.fail(
                "block_ip should not raise an exception even if iptables is not found"
            )


def test_block_ip_when_input_nic_ip(mitigator):
    with (
        patch.object(mitigator, "_valid_ip", return_value=False),
        patch.object(mitigator, "_iptables_rule_exists") as mock_exists,
        patch.object(mitigator, "_iptables_add_rule") as mock_add,
        patch.object(mitigator, "_schedule_unblock") as mock_schedule,
    ):
        mitigator.block_ip("8.8.8.8")
        mock_exists.assert_not_called()
        mock_add.assert_not_called()
        mock_schedule.assert_not_called()


def test_schedule_unblock(mitigator):
    ip = "8.8.8.8"

    with (
        patch("ddos_martummai.mitigator.threading.Thread") as mock_thread_class,
        patch("ddos_martummai.mitigator.time.sleep") as mock_sleep,
        patch("ddos_martummai.mitigator.subprocess.run") as mock_run,
    ):
        mitigator._schedule_unblock(ip)

        thread_target_func = mock_thread_class.call_args[1]["target"]
        thread_target_func()

        mock_sleep.assert_called_once_with(60)
        mock_run.assert_called_once_with(
            [IPTABLES_PATH, "-D", "INPUT", "-s", ip, "-j", "DROP"], check=False
        )


def test_schedule_unblock_error_exception(mitigator, caplog):
    ip = "8.8.8.8"

    with (
        patch("ddos_martummai.mitigator.threading.Thread") as mock_thread_class,
        patch("ddos_martummai.mitigator.time.sleep"),
        patch(
            "ddos_martummai.mitigator.subprocess.run",
            side_effect=Exception("Iptables Crash"),
        ),
    ):
        mitigator._schedule_unblock(ip)

        thread_target_func = mock_thread_class.call_args[1]["target"]
        thread_target_func()

        assert "Error unblocking IP: Iptables Crash" in caplog.text


def test_valid_ip_psutil_exception(mitigator, caplog):
    with patch(
        "ddos_martummai.mitigator.psutil.net_if_addrs",
        side_effect=Exception("OS Error"),
    ):
        assert mitigator._valid_ip("8.8.8.8") is True
        assert "Error checking interface IPs: OS Error" in caplog.text
