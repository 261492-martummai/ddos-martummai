import logging
import smtplib
import subprocess  # nosec B404
import threading
import time
from email.mime.text import MIMEText

import psutil

from ddos_martummai.init_models import AppConfig

logger = logging.getLogger("MITIGATOR")


class Mitigator:
    def __init__(self, config: AppConfig):
        self.config = config

    def _schedule_unblock(self, ip_address: str):
        def unblock():
            time.sleep(self.config.mitigation.block_duration_seconds)
            try:
                logger.info(f"[MITIGATION] Unblocking IP: {ip_address}")
                subprocess.run(
                    [
                        "/usr/sbin/iptables",
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
                logger.error(f"[!] Error unblocking IP: {e}")

        t = threading.Thread(target=unblock, daemon=True)
        t.start()

    def _validate_smtp_config(self):
        if (
            not self.config.mitigation.admin_email
            or not self.config.mitigation.smtp_user
        ):
            logger.warning("Email alerting is disabled: missing config.")
            return

        try:
            with smtplib.SMTP(
                self.config.mitigation.smtp_server,
                self.config.mitigation.smtp_port,
                timeout=5,
            ) as server:
                server.starttls()
                server.login(
                    self.config.mitigation.smtp_user,
                    self.config.mitigation.smtp_password,
                )
            logger.info("SMTP configuration validated successfully.")
        except Exception as e:
            logger.error(f"SMTP validation failed: {e}. You might not receive alerts!")

    def _valid_ip(self, ip_address: str) -> bool:
        if not ip_address or ip_address == "Unknown":
            logger.warning(f"Invalid IP address: {ip_address}")
            return False
        target_interface = self.config.system.interface
        try:
            addrs = psutil.net_if_addrs()
            if target_interface in addrs:
                interface_ips = [addr.address for addr in addrs[target_interface]]

                if ip_address in interface_ips:
                    logger.warning(
                        f"Blocking skipped: IP {ip_address} matches system interface {target_interface}"
                    )
                    return False
        except Exception as e:
            logger.error(f"Error checking interface IPs: {e}")

        return True

    def send_alert(self, ip_address: str, flow_info: str):
        if (
            not self.config.mitigation.admin_email
            or not self.config.mitigation.smtp_user
        ):
            return

        logger.info(f"Initiating email alert for {ip_address}...")
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

        def send_async():
            try:
                with smtplib.SMTP(
                    self.config.mitigation.smtp_server, self.config.mitigation.smtp_port
                ) as server:
                    server.starttls()
                    server.login(
                        self.config.mitigation.smtp_user,
                        self.config.mitigation.smtp_password,
                    )
                    server.send_message(msg)
                logger.info(
                    f"[ALERT] Email sent to {self.config.mitigation.admin_email}"
                )
            except Exception as e:
                logger.error(f"Failed to send email: {e}")

        # Run in thread to not block main processing
        threading.Thread(target=send_async, daemon=False).start()

    def block_ip(self, ip_address: str):
        if not self._valid_ip(ip_address):
            return

        logger.info(f"[MITIGATION] Blocking IP: {ip_address}")
        try:
            # Check if rule exists to avoid duplicates
            check = subprocess.run(
                ["/usr/sbin/iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )  # nosec B603

            if check.returncode != 0:
                subprocess.run(
                    [
                        "/usr/sbin/iptables",
                        "-A",
                        "INPUT",
                        "-s",
                        ip_address,
                        "-j",
                        "DROP",
                    ],
                    check=True,
                )  # nosec B603
                self._schedule_unblock(ip_address)
        except subprocess.CalledProcessError as e:
            logger.error(f"Error modifying iptables: {e}")
        except FileNotFoundError:
            logger.critical(
                "iptables command not found. Ensure you are running on Linux as root."
            )
