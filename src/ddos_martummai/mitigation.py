import logging
import smtplib
import subprocess  # nosec B404
import threading
import time
from email.mime.text import MIMEText

from .config_loader_oldl import MitigationConfig

logger = logging.getLogger("ddos-martummai")


class Mitigator:
    def __init__(self, config: MitigationConfig):
        self.config = config

    def block_ip(self, ip_address: str):
        if not ip_address or ip_address == "Unknown":
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

    def _schedule_unblock(self, ip_address: str):
        def unblock():
            time.sleep(self.config.block_duration_seconds)
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

    def send_alert(self, ip_address: str, flow_info: str):
        if not self.config.admin_email or not self.config.smtp_user:
            return

        msg = MIMEText(
            f"DDoS Attack Detected from IP: {ip_address}\n\nFlow Details:\n{flow_info}"
        )
        msg["Subject"] = f"ALERT: DDoS Attack Detected - {ip_address}"
        msg["From"] = self.config.smtp_user
        msg["To"] = self.config.admin_email

        def send_async():
            try:
                with smtplib.SMTP(
                    self.config.smtp_server, self.config.smtp_port
                ) as server:
                    server.starttls()
                    server.login(self.config.smtp_user, self.config.smtp_password)
                    server.send_message(msg)
                logger.info(f"[ALERT] Email sent to {self.config.admin_email}")
            except Exception as e:
                logger.error(f"Failed to send email: {e}")

        # Run in thread to not block main processing
        threading.Thread(target=send_async, daemon=True).start()
