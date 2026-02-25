import socket
from dataclasses import asdict
from pathlib import Path
from typing import List

import psutil
import questionary
import yaml
from rich.console import Console
from rich.panel import Panel

from ddos_martummai.init_models import AppConfig
from ddos_martummai.util.path_helper import get_app_paths

console = Console()
APP_PATHS = get_app_paths()


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
        try:
            console.print(
                Panel.fit(
                    "Welcome to DDoS Martummai Guard System Setup", style="bold green"
                )
            )
            console.print("Configuration is REQUIRED to proceed.\n")

            # 1. Setup Network Interface
            self._setup_interface()

            # 2. Setup Email (Mitigation)
            self._setup_email()

            # 3. Setup Blocking (Mitigation)
            self._setup_blocking()

            # 4. Setup Paths
            self._setup_path()

            # 5. Save Config
            return self._save_config()
        except KeyboardInterrupt:
            console.print("\n[red]Setup cancelled by user.[/red]")
            return False

    def _setup_interface(self):
        while True:
            interfaces = self._get_network_interfaces()
            selected = None

            if not interfaces:
                console.print(
                    "[bold red]Error: No network interfaces detected![/bold red]"
                )
                selected = questionary.text(
                    "Enter Network Interface manually (e.g., eth0):",
                    validate=lambda text: True
                    if len(text.strip()) > 0
                    else "Interface name cannot be empty!",
                ).ask()
            else:
                selected = questionary.select(
                    "Select the Network Interface to monitor (Required):",
                    choices=interfaces,
                ).ask()

            if selected is None:
                raise KeyboardInterrupt

            if selected:
                self.app_config.system.interface = selected
                console.print(f"[green]Selected Interface: {selected}[/green]")
                break
            else:
                console.print(
                    "[bold red](!) Interface is required to run the detector.[/bold red]"
                )

    def _setup_email(self):
        def validate_non_empty(text):
            if len(text.strip()) > 0:
                return True
            return "This field is required!"

        if questionary.confirm("Do you want to enable Email Alerts?").ask():
            mit = self.app_config.mitigation
            console.print(
                "[cyan]Please provide SMTP details (All fields required):[/cyan]"
            )
            mit.admin_email = questionary.text(
                "Admin Email (Receiver):", validate=validate_non_empty
            ).ask()
            mit.smtp_user = questionary.text(
                "SMTP User (Sender Email):", validate=validate_non_empty
            ).ask()
            mit.smtp_password = questionary.password(
                "SMTP Password:", validate=validate_non_empty
            ).ask()
            mit.smtp_server = questionary.text(
                "SMTP Server:", default="smtp.gmail.com", validate=validate_non_empty
            ).ask()
            mit.smtp_port = int(
                questionary.text(
                    "SMTP Port:",
                    default="587",
                    validate=lambda text: True
                    if text.isdigit()
                    else "Port must be a number",
                ).ask()
            )

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

    def _setup_path(self):
        data_dir = APP_PATHS["data_dir"]
        log_file_path = APP_PATHS["log_file"]
        token_file_path = APP_PATHS["token_file"]

        self.app_config.system.csv_output_path = str(data_dir)
        self.app_config.system.log_file_path = str(log_file_path)
        self.app_config.system.token_file_path = str(token_file_path)
        self.app_config.system.test_mode_output_path = str(
            data_dir / "test_results.csv"
        )

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
        except PermissionError:
            console.print("\n[bold red]Permission Denied![/bold red]")
            console.print(f"Cannot write to [yellow]{self.config_path}[/yellow]")
            console.print("Please run with [bold]sudo[/bold].")
            return False
        except Exception as e:
            console.print(f"\n[bold red]Failed to save config: {e}[/bold red]")
            return False
