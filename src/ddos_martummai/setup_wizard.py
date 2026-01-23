import os

import psutil
import questionary
import yaml
from rich.console import Console
from rich.panel import Panel

console = Console()


def get_network_interfaces():
    try:
        return list(psutil.net_if_addrs().keys())
    except Exception:
        return []


def run_setup_wizard(config_path: str, default_config: dict) -> bool:
    console.print(
        Panel.fit("Welcome to DDoS Martummai Guard System Setup", style="bold green")
    )
    console.print("Configuration is missing or incomplete. Let's set it up.\n")

    # 1. Select Interface
    interfaces = get_network_interfaces()
    if not interfaces:
        console.print("[bold red]Error: No network interfaces found![/bold red]")
        # Allow manual entry if detection fails
        selected_interface = questionary.text(
            "Enter Network Interface manually (e.g., eth0):"
        ).ask()
    else:
        selected_interface = questionary.select(
            "Select the Network Interface to monitor:", choices=interfaces
        ).ask()

    if not selected_interface:
        return False

    # 2. Email Setup
    enable_email = questionary.confirm("Do you want to enable Email Alerts?").ask()

    mitigation_config = default_config["mitigation"]
    if enable_email:
        mitigation_config["admin_email"] = questionary.text(
            "Admin Email (Receiver):"
        ).ask()
        mitigation_config["smtp_user"] = questionary.text(
            "SMTP User (Sender Email):"
        ).ask()
        mitigation_config["smtp_password"] = questionary.password(
            "SMTP Password:"
        ).ask()
        mitigation_config["smtp_server"] = questionary.text(
            "SMTP Server:", default="smtp.gmail.com"
        ).ask()
        mitigation_config["smtp_port"] = int(
            questionary.text("SMTP Port:", default="587").ask()
        )

    # 3. Blocking Setup
    enable_blocking = questionary.confirm(
        "Do you want to enable Auto-IP Temporary Blocking?"
    ).ask()
    mitigation_config["enable_blocking"] = enable_blocking
    if enable_blocking:
        block_duration = questionary.text(
            "Block Duration in seconds:", default="100"
        ).ask()
        mitigation_config["block_duration_seconds"] = int(block_duration)

    # Prepare final config
    new_config = default_config.copy()
    new_config["system"]["interface"] = selected_interface
    new_config["mitigation"] = mitigation_config

    # Ensure directory exists
    try:
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, "w") as f:
            yaml.dump(new_config, f, default_flow_style=False)

        console.print(
            f"\n[bold green]Configuration saved to: {config_path}[/bold green]"
        )
        return True
    except Exception as e:
        console.print(f"[bold red]Failed to save config: {e}[/bold red]")
        return False
