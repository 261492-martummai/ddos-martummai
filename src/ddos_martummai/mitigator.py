import logging
import smtplib
import subprocess  # nosec B404
import threading
import time
from email.mime.text import MIMEText

import psutil

from ddos_martummai.init_models import AppConfig
from ddos_martummai.web.monitor import push_mitigation_event

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

    def _is_email_enabled(self) -> bool:
        """Check if email alerting is configured."""
        return bool(
            self.config.mitigation.admin_email and self.config.mitigation.smtp_user
        )

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
        if not self._is_email_enabled():
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

    def send_alert(self, ip_address: str, flow_info: str) -> None:
        if not self._is_email_enabled():
            return

        logger.info(f"Initiating email alert for {ip_address}...")
        msg = self._create_alert_message(ip_address, flow_info)
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
        if not self._valid_ip(ip_address):
            return

        push_mitigation_event(ip_address)

        logger.debug(f"{LOG_MITIGATION} Blocking IP: {ip_address}")
        # try:
        #     # Check if rule exists to avoid duplicates
        #     if not self._iptables_rule_exists(ip_address):
        #         logger.info(f"{LOG_MITIGATION} Blocking IP: {ip_address}")
        #         self._iptables_add_rule(ip_address)
        #         self._schedule_unblock(ip_address)
        # except FileNotFoundError:
        #     # Already logged in _iptables_rule_exists
        #     pass
