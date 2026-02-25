import logging
import smtplib
import subprocess  # nosec B404
import threading
import time
from email.mime.text import MIMEText
from typing import List, Union

import psutil

from ddos_martummai.init_models import AppConfig

logger = logging.getLogger("MITIGATOR")

# Constants
IPTABLES_PATH = "/usr/sbin/iptables"
SMTP_TIMEOUT = 5
INVALID_IP = "Unknown"
LOG_MITIGATION = "[MITIGATION]"
LOG_ALERT = "[ALERT]"
LOG_ERROR = "[!]"


class Mitigator:
    def __init__(self, config: AppConfig):
        self.config = config
        self.first_blocking_warning_logged = False
        self.first_email_warning_logged = False

    def _schedule_unblock(self, ip_address: str) -> None:
        def unblock() -> None:
            time.sleep(self.config.mitigation.block_duration_seconds)
            try:
                logger.info(f"{LOG_MITIGATION} Unblocking IP: {ip_address}")
                subprocess.run(
                    [
                        IPTABLES_PATH,
                        "-D",
                        "INPUT",
                        "-s",
                        ip_address,
                        "-j",
                        "DROP",
                    ],
                    check=False,
                )  # nosec B603
            except Exception as e:
                logger.error(f"{LOG_ERROR} Error unblocking IP: {e}")

        threading.Thread(target=unblock, daemon=False).start()

    def _email_alert_enabled(self) -> bool:
        """Check if email alerting is configured."""
        if not self.config.mitigation.enable_email_alert:
            if not self.first_email_warning_logged:
                logger.warning("Email alerting disabled in config.")
                self.first_email_warning_logged = True
        return self.config.mitigation.enable_email_alert

    def _ip_blocking_enabled(self) -> bool:
        """Check if blocking is enabled in config."""
        if not self.config.mitigation.enable_blocking:
            if not self.first_blocking_warning_logged:
                logger.warning("IP blocking disabled in config.")
                self.first_blocking_warning_logged = True
        return self.config.mitigation.enable_blocking

    def _create_smtp_connection(self):
        """Create and authenticate SMTP connection."""
        server = smtplib.SMTP(
            self.config.mitigation.smtp_server,
            self.config.mitigation.smtp_port,
            timeout=SMTP_TIMEOUT,
        )
        server.starttls()
        server.login(
            self.config.mitigation.smtp_user,
            self.config.mitigation.smtp_password,
        )
        return server

    def _validate_smtp_config(self) -> None:
        if not self._email_alert_enabled():
            logger.warning("Email alerting is disabled: missing config.")
            return

        try:
            with self._create_smtp_connection():
                pass
            logger.info("SMTP configuration validated successfully.")
        except Exception as e:
            logger.error(f"SMTP validation failed: {e}. You might not receive alerts!")

    def _valid_ip(self, ip_address: str) -> bool:
        if not ip_address or ip_address == INVALID_IP:
            logger.warning(f"Invalid IP address: {ip_address}")
            return False
        target_interface = self.config.system.interface
        try:
            addrs = psutil.net_if_addrs()
            if target_interface in addrs:
                interface_ips = [addr.address for addr in addrs[target_interface]]

                if ip_address in interface_ips:
                    logger.debug(
                        f"Blocking skipped: IP {ip_address} matches system interface {target_interface}"
                    )
                    return False
        except Exception as e:
            logger.error(f"Error checking interface IPs: {e}")

        return True

    def _create_alert_message(self, ip_address: str, flow_info: str) -> MIMEText:
        """Create email alert message."""
        msg = MIMEText(
            f"DDoS Attack Detected from IP: {ip_address}\n\n"
            f"Detection Time   : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}\n"
            f"System Interface : {self.config.system.interface}\n"
            f"IP               : {ip_address}\n\n"
            f"Action Taken     : IP BLOCKED for {self.config.mitigation.block_duration_seconds} seconds\n\n"
            f"--- FLOW STATISTICS ---\n"
            f"{flow_info}\n"
        )

        msg["Subject"] = f"ALERT: DDoS Attack Detected - {ip_address}"
        msg["From"] = self.config.mitigation.smtp_user
        msg["To"] = self.config.mitigation.admin_email

        return msg

    def _send_email_async(self, msg: MIMEText) -> None:
        """Send email asynchronously."""

        def send_async() -> None:
            try:
                with self._create_smtp_connection() as server:
                    server.send_message(msg)
                logger.info(
                    f"{LOG_ALERT} Email sent to {self.config.mitigation.admin_email}"
                )
            except Exception as e:
                logger.error(f"Failed to send email: {e}")

        # Run in thread to not block main processing
        threading.Thread(target=send_async, daemon=False).start()

    def send_alert(self, ip_address: Union[str, List[str]], flow_info: str) -> None:
        if not self._email_alert_enabled():
            return

        if isinstance(ip_address, str):
            ip_list = [ip_address]
        else:
            ip_list = ip_address

        valid_ips = [ip for ip in ip_list if self._valid_ip(ip)]

        if not valid_ips:
            return

        ip_csv_str = ", ".join(valid_ips)

        logger.info(f"Initiating email alert for {ip_csv_str}...")
        msg = self._create_alert_message(ip_csv_str, flow_info)
        self._send_email_async(msg)

    def _iptables_rule_exists(self, ip_address: str) -> bool:
        """Check if iptables rule already exists for IP."""
        try:
            result = subprocess.run(
                [IPTABLES_PATH, "-C", "INPUT", "-s", ip_address, "-j", "DROP"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )  # nosec B603
            return result.returncode == 0
        except FileNotFoundError:
            logger.critical(
                "iptables command not found. Ensure you are running on Linux as root."
            )
            raise

    def _iptables_add_rule(self, ip_address: str) -> None:
        """Add iptables rule to block IP."""
        try:
            subprocess.run(
                [IPTABLES_PATH, "-A", "INPUT", "-s", ip_address, "-j", "DROP"],
                check=True,
            )  # nosec B603
        except subprocess.CalledProcessError as e:
            logger.error(f"Error modifying iptables: {e}")
            raise

    def block_ip(self, ip_address: str) -> None:
        if not self._ip_blocking_enabled():
            return

        if not self._valid_ip(ip_address):
            return

        try:
            # Check if rule exists to avoid duplicates
            if not self._iptables_rule_exists(ip_address):
                logger.info(f"Temporary Blocking IP: {ip_address}")
                self._iptables_add_rule(ip_address)
                self._schedule_unblock(ip_address)
        except FileNotFoundError:
            # Already logged in _iptables_rule_exists
            pass
