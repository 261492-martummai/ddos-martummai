from __future__ import annotations

import logging
import smtplib
import subprocess  # nosec B404
import threading
import time
from dataclasses import asdict
from email.mime.text import MIMEText
from multiprocessing import Queue
from typing import List, Union

import psutil

from ddos_martummai.init_models import AppConfig, BlockDetail

logger = logging.getLogger("MITIGATOR")

# Constants
IPTABLES_PATH = "/usr/sbin/iptables"
IPSET_PATH = "/usr/sbin/ipset"
IPSET_NAME = "ddos_martummai_blocklist"
SMTP_TIMEOUT = 5
INVALID_IP = "Unknown"
LOG_MITIGATION = "[MITIGATION]"
LOG_ALERT = "[ALERT]"
LOG_ERROR = "[!]"


class Mitigator:
    def __init__(
        self, config: AppConfig, mitigation_event_queue: Queue[dict[str, str]]
    ):
        self.config = config
        self.mitigation_event_queue = mitigation_event_queue
        self.first_blocking_warning_logged = False
        self.first_email_warning_logged = False
        self.alert_cache: dict[str, float] = {}
        self.alert_cooldown_seconds = config.mitigation.alert_cooldown_seconds

        if self._ip_blocking_enabled():
            self._setup_infrastructure()

    def send_alert(self, ip_address: Union[str, List[str]], flow_info: str) -> None:
        if not self._email_alert_enabled():
            return

        ip_list = [ip_address] if isinstance(ip_address, str) else ip_address

        ips_to_alert = self._filter_ips_for_alert(ip_list)

        if not ips_to_alert:
            return

        ip_csv_str = ", ".join(ips_to_alert)

        logger.info(f"Initiating email alert for {ip_csv_str}...")
        msg = self._create_alert_message(ip_csv_str, flow_info)
        self._send_email_async(msg)

    def block_ip(self, ip_address: str) -> bool:
        if not self._ip_blocking_enabled() or not self._valid_ip(ip_address):
            return False

        duration = self.config.mitigation.block_duration_seconds

        try:
            result = subprocess.run(
                [IPSET_PATH, "add", IPSET_NAME, ip_address, "timeout", str(duration)],
                capture_output=True,
                text=True,
                check=False,
            )  # nosec B603
            if result.returncode == 0:
                logger.info(
                    f"{LOG_MITIGATION} IP {ip_address} blocked for {duration} seconds (managed by ipset)."
                )
                self._push_mitigation_event(ip_address)
                return True
            else:
                if "already added" in result.stderr:
                    logger.debug(
                        f"{LOG_MITIGATION} IP {ip_address} is already blocked. Skipping (timeout not reset)."
                    )
                else:
                    logger.error(
                        f"{LOG_ERROR} Failed to add IP to ipset: {result.stderr.strip()}"
                    )
                return False
        except Exception as e:
            logger.error(f"{LOG_ERROR} Error modifying ipset: {e}")
            return False

    def _setup_infrastructure(self) -> None:
        try:
            subprocess.run(
                [IPSET_PATH, "create", IPSET_NAME, "hash:ip", "timeout", "0"],
                stderr=subprocess.DEVNULL,
                check=False,
            )  # nosec B603

            check_rule = subprocess.run(
                [
                    IPTABLES_PATH,
                    "-C",
                    "INPUT",
                    "-m",
                    "set",
                    "--match-set",
                    IPSET_NAME,
                    "src",
                    "-j",
                    "DROP",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )  # nosec B603

            if check_rule.returncode != 0:
                subprocess.run(
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
                )  # nosec B603
                logger.info(
                    f"{LOG_MITIGATION} Infrastructure initialized: ipset '{IPSET_NAME}' linked to iptables."
                )

        except FileNotFoundError:
            logger.critical(
                "ipset or iptables command not found. Please install 'ipset'."
            )
            raise
        except Exception as e:
            logger.error(f"{LOG_ERROR} Failed to setup infrastructure: {e}")

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

    def _filter_ips_for_alert(self, ip_list: List[str]) -> List[str]:
        now = time.time()
        valid_ips = []

        for ip in ip_list:
            if not self._valid_ip(ip):
                continue

            if ip in self.alert_cache:
                if now - self.alert_cache[ip] < self.alert_cooldown_seconds:
                    logger.debug(f"{LOG_ALERT} Muted alert for {ip} (Cooldown active).")
                    continue

            self.alert_cache[ip] = now
            valid_ips.append(ip)

        # Cleanup old entries in alert cache
        self.alert_cache = {
            k: v
            for k, v in self.alert_cache.items()
            if now - v < self.alert_cooldown_seconds
        }

        return valid_ips

    def _push_mitigation_event(self, ip_address: str) -> None:
        try:
            event_data = BlockDetail(ip=ip_address, time=time.strftime("%H:%M:%S"))
            self.mitigation_event_queue.put(asdict(event_data))
        except Exception as e:
            logger.error(f"Failed to push mitigation event: {e}")
