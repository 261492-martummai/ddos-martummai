import subprocess  # nosec B404
import sys

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Initialize Rich Console
console = Console()


def print_header():
    """Prints the project logo in Block/Tech style."""
    logo = r"""
 ███    ███  █████  ██████  ████████ ██   ██ ███    ███ ███    ███  █████  ██ 
 ████  ████ ██   ██ ██   ██    ██    ██   ██ ████  ████ ████  ████ ██   ██ ██ 
 ██ ████ ██ ███████ ██████     ██    ██   ██ ██ ████ ██ ██ ████ ██ ███████ ██ 
 ██  ██  ██ ██   ██ ██   ██    ██    ██   ██ ██  ██  ██ ██  ██  ██ ██   ██ ██ 
 ██      ██ ██   ██ ██   ██    ██     █████  ██      ██ ██      ██ ██   ██ ██ 
    """

    console.print(Align.center(Text(logo, style="bold #E3765E")))

    # Subtitle text
    subtitle = Text(
        "DDoS DETECTION SYSTEM | QUALITY CONTROL PIPELINE", style="dim white"
    )
    console.print(Align.center(subtitle))
    console.print("\n")


def run_checks():
    print_header()

    steps = [
        {
            "name": "FORMATTING & LINTING (Ruff)",
            "commands": [
                ["ruff", "format", "src/", "tests/"],
                ["ruff", "check", "--fix", "src/", "tests/"],
            ],
        },
        {
            "name": "STATIC TYPE CHECK (Mypy)",
            "commands": [
                ["mypy", "src/"],
            ],
        },
        {
            "name": "SECURITY AUDIT (Bandit)",
            "commands": [
                ["bandit", "-r", "src/", "-c", "pyproject.toml", "--exclude", "tests/"],
            ],
        },
        {
            "name": "UNIT TESTING (Pytest)",
            "commands": [
                [
                    "pytest",
                    "--cov=ddos_martummai",
                    "--cov-report=term-missing",
                    "tests/",
                    "-v",
                ],
            ],
        },
    ]

    total_steps = len(steps)

    for i, step in enumerate(steps, 1):
        console.rule(f"[bold white]STEP {i}/{total_steps} : {step['name']}")

        for cmd in step["commands"]:
            cmd_str = " ".join(cmd)
            console.print(f"[dim]Executing: {cmd_str}[/dim]", highlight=False)

            try:
                subprocess.run(cmd, check=True)  # nosec B603
            except subprocess.CalledProcessError:
                console.print()
                console.print(
                    Panel(
                        f"[bold red]FAILED[/bold red]\n\n"
                        f"The command returned a non-zero exit code.\n"
                        f"Command: [white]{cmd_str}[/white]",
                        title="[bold red]Pipeline Halted[/bold red]",
                        border_style="red",
                    )
                )
                sys.exit(1)

        console.print(Align.right("[bold green][ PASS ][/bold green]"))
        console.print()

    console.rule("[bold #E3765E]PIPELINE COMPLETE")
    console.print(
        Panel(
            Align.center(
                "[bold green]ALL QUALITY CHECKS PASSED SUCCESSFULLY[/bold green]"
            ),
            border_style="#E3765E",
            padding=(1, 2),
        )
    )


if __name__ == "__main__":
    run_checks()
