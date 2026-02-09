import os
import socket

import psutil
import questionary
import yaml
from rich.console import Console
from rich.panel import Panel

console = Console()
def get_network_interfaces():
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
            options.append(questionary.Choice(title=display_text, value=interface_name))
        return options
    
    except Exception as e:
        console.print(f"[yellow]Warning: Could not list interfaces ({e})[/yellow]")
        return []

def run_setup_wizard(config_path: str, default_config: dict) -> bool:
    console.print(Panel.fit("Welcome to DDoS Martummai Guard System Setup", style="bold green"))
    console.print("Configuration is missing or incomplete. Let's set it up.\n")
    
    # choose network interface
    interfaces = get_network_interfaces()
    if not interfaces:
        console.print("[bold red]Error: No network interfaces found![/bold red]")
        selected_interface = questionary.text("Enter Network Interface manually (e.g., eth0):").ask()
    else:
        selected_interface = questionary.select("Select the Network Interface to monitor:", choices=interfaces).ask()
    
    if not selected_interface:
        return False
    
    # email alerts setting
    enable_email = questionary.confirm("Do you want to enable Email Alerts?").ask()
    mitigation_config = default_config["mitigation"]
    
    if enable_email:
        mitigation_config["admin_email"] = questionary.text("Admin Email (Receiver):").ask()
        mitigation_config["smtp_user"] = questionary.text("SMTP User (Sender Email):").ask()
        mitigation_config["smtp_password"] = questionary.password("SMTP Password:").ask()
        mitigation_config["smtp_server"] = questionary.text("SMTP Server:", default="smtp.gmail.com").ask()
        mitigation_config["smtp_port"] = int(questionary.text("SMTP Port:", default="587").ask())
    
    # IP blocking setting
    enable_blocking = questionary.confirm("Do you want to enable Auto-IP Temporary Blocking?").ask()
    mitigation_config["enable_blocking"] = enable_blocking
    
    if enable_blocking:
        block_duration = questionary.text("Block Duration in seconds:", default="100").ask()
        mitigation_config["block_duration_seconds"] = int(block_duration)
    
    # save config
    new_config = default_config.copy()
    new_config["system"]["interface"] = selected_interface
    new_config["mitigation"] = mitigation_config
    
    try:
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, "w") as f:
            yaml.dump(new_config, f, default_flow_style=False)
        
        console.print(f"\n[bold green]Configuration saved to: {config_path}[/bold green]")
        console.print("You can change any settings later.\n")
        return True
    
    except Exception as e:
        console.print(f"[bold red]Failed to save config: {e}[/bold red]")
        return False