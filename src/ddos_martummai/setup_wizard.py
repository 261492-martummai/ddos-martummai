import socket
from dataclasses import asdict
from pathlib import Path
from typing import List

import psutil
import questionary
import yaml
from rich.console import Console
from rich.panel import Panel

from ddos_martummai.config_loader import AppConfig

console = Console()


class SetupWizard:
    def __init__(self, config_path: Path, app_config: AppConfig):
        self.config_path = config_path
        self.app_config = app_config

    def _get_network_interfaces(self) -> List[questionary.Choice]:
        options = []
        try:
            net_addrs = psutil.net_if_addrs()
            for interface_name, snics in net_addrs.items():
                ip_label = "No IPv4"
                for snic in snics:
                    if snic.family == socket.AF_INET:
                        ip_label = snic.address
                        break
                display_text = f"{interface_name:<10} - {ip_label}"
                options.append(
                    questionary.Choice(title=display_text, value=interface_name)
                )
            return options
        except Exception as e:
            console.print(f"[yellow]Warning: Could not list interfaces ({e})[/yellow]")
            return []

    def run(self) -> bool:
        console.print(
            Panel.fit(
                "Welcome to DDoS Martummai Guard System Setup", style="bold green"
            )
        )
        console.print("Configuration is missing or incomplete. Let's set it up.\n")

        # 1. Setup Network Interface
        if not self._setup_interface():
            return False

        # 2. Setup Email (Mitigation)
        self._setup_email()

        # 3. Setup Blocking (Mitigation)
        self._setup_blocking()

        # 4. Save Config
        return self._save_config()

    def _setup_interface(self) -> bool:
        interfaces = self._get_network_interfaces()

        if not interfaces:
            console.print("[bold red]Error: No network interfaces found![/bold red]")
            selected = questionary.text(
                "Enter Network Interface manually (e.g., eth0):"
            ).ask()
        else:
            selected = questionary.select(
                "Select the Network Interface to monitor:", choices=interfaces
            ).ask()

        if selected:
            self.app_config.system.interface = selected
            return True
        return False

    def _setup_email(self):
        if questionary.confirm("Do you want to enable Email Alerts?").ask():
            mit = self.app_config.mitigation
            mit.admin_email = questionary.text("Admin Email (Receiver):").ask()
            mit.smtp_user = questionary.text("SMTP User (Sender Email):").ask()
            mit.smtp_password = questionary.password("SMTP Password:").ask()
            mit.smtp_server = questionary.text(
                "SMTP Server:", default="smtp.gmail.com"
            ).ask()
            mit.smtp_port = int(questionary.text("SMTP Port:", default="587").ask())

    def _setup_blocking(self):
        if questionary.confirm(
            "Do you want to enable Auto-IP Temporary Blocking?"
        ).ask():
            mit = self.app_config.mitigation
            mit.enable_blocking = True
            mit.block_duration_seconds = int(
                questionary.text("Block Duration in seconds:", default="100").ask()
            )
        else:
            self.app_config.mitigation.enable_blocking = False

    def _save_config(self) -> bool:
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)

            config_dict = asdict(self.app_config)

            with self.config_path.open("w", encoding="utf-8") as f:
                yaml.dump(config_dict, f, default_flow_style=False)

            console.print(
                f"\n[bold green]Configuration saved to: {self.config_path}[/bold green]"
            )
            return True
        except Exception as e:
            console.print(f"[bold red]Failed to save config: {e}[/bold red]")
            return False
