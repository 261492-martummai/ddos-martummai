# DDoS MarTumMai Detection System

This repository contains the source code for the Machine Learning-based DDoS attack detection system. This document serves as a guide for the development team to set up the environment, contribute code, and understand the project workflow.

## Installation

If you simply want to **use** the DDoS detection system on your server, you don't need to clone the code.

[![Latest Release](https://img.shields.io/github/v/release/261492-martummai/ddos-martummai?label=Latest%20Release&style=for-the-badge&color=success)](https://github.com/261492-martummai/ddos-martummai/releases/latest)

### Steps to Install

1.  **Download**: Click the button above or go to the [Releases Page](https://github.com/261492-martummai/ddos-martummai/releases/latest).
2.  Download the `.deb` file (e.g., `ddos-martummai_1.0.0_amd64.deb`) to your machine.
3.  **Install**: Open your terminal in the folder where you downloaded the file and run:

    ```bash
    # Update apt first (recommended)
    sudo apt update

    # Install the package (replace filename with the actual one)
    sudo apt install ./ddos-martummai_*.deb
    ```

    _(Note: Using `./` before the filename is important specifically when installing a local .deb file with apt)_

4.  **Run**: Choose how you want to run the application (Service vs Standalone).

    #### Option A: Run as a Service (Daemon)

    Recommended for production environments.

    ```bash
    # 1. Setup Service Config (Run once)
    sudo martummai-setup

    # 2. Start the Service
    sudo systemctl start ddos-martummai

    # 3. (Optional) Enable at startup
    sudo systemctl enable ddos-martummai

    ```

    #### Option B: Run Standalone (CLI)

    Useful for testing or manual monitoring.

    **View Help & Options:**

    ```text
    Usage: ddos-martummai [OPTIONS]

        DDoS MarTumMai Guard: A Fine-Tuned Machine Learning DDoS detection system.

    Options:
        Modes (Default: Real-time Monitor):
            -t, --test-mode               Run in Test/Simulation mode (requires -f).
            --setup                       Run the initial setup wizard and exit.
        Test Arguments:                 (Required for --test-mode)
            -f, --file-path FILE          Input pcap or csv file path for testing.
        Configuration Options:
            -c, --config-file FILE        Path to configuration file.
            -o, --override-env            Override config with Environment Variables.
        General Options:
            -v, --verbose                 Enable debug logging.
        --help                          Show this message and exit.
    ```

    **Run in Live Mode:**
    (Requires root privileges to capture packets)

    ```bash
    sudo ddos-martummai

    ```

    **Run in Test Mode:**
    (Simulate detection using a prepared flow file)

    ```bash
    sudo ddos-martummai -t -f ./flow.csv

    ```

## Development Setup (For Developers)

This section is for developers who want to contribute to the project codebase.

### Prerequisites

Before setting up the project, ensure that you have the following installed on your local machine:

- **Python 3.13** or higher
- **Git** (for version control)
- **uv** (An extremely fast Python package installer and resolver)

To install `uv`, you can follow this : [Uv Installation Document](https://docs.astral.sh/uv/getting-started/installation/#standalone-installer)

### Installation Step

Follow these steps to set up the development environment:

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/261492-martummai/ddos-martummai.git
    cd ddos-martummai
    ```

2.  **Install dependencies:**
    This project uses `uv` for dependency management. This command will create a virtual environment and install all required packages (including development tools).
    ```bash
    uv sync --dev
    ```
3.  **Run the application:**

    To start the detection system in live, use the following command:

    ```bash
    uv run ddos-martummai
    ```

    To start detect from csv in test mode, use the following command:

    ```bash
    uv run ddos-martummai -tf ./cicflows.csv
    ```

## VS Code Configuration (Recommended)

To ensure code consistency and enable automatic formatting on save, we recommend using Visual Studio Code with the **Ruff** extension.

1.  Install the **Ruff** extension (Publisher: Astral Software).
2.  Folder named `.vscode` will activate for ruff setting.

## Development Workflow

We use a strict set of tools to maintain code quality. Please run this command locally before submitting a Pull Request.

```bash
uv run checker
```

## Branching and Contribution Strategy

This project adheres to a strict Pull Request (PR) workflow. Direct pushes to protected branches are disabled.

### Protected Branches

- **main**: The production-ready branch. Contains only stable, tested code.
- **dev**: The integration branch. Features are merged here first for integration testing.

### Workflow Steps

1.  **Create a Feature Branch**: Always create a new branch from `dev`.
    ```bash
    git checkout -b feature/your-feature-name
    ```
2.  **Develop and Test**: Write your code and ensure `uv run pytest` passes locally.
3.  **Push and Open PR**: Push your branch to GitHub and open a Pull Request targeting `dev` (or `main` for hotfixes).
4.  **CI/CD Checks**: The GitHub Actions pipeline will automatically run. It checks:
    - Code Formatting (Ruff)
    - Linting (Ruff)
    - Security (Bandit)
    - Unit Tests (Pytest)
5.  **Update Branch**: If the target branch has changed, you must update your branch and ensure tests still pass.
    - _GitHub may block the merge if your branch is out of date._
6.  **Merge**: Once CI passes and code is reviewed, the PR can be merged.

## Release Process

We use Git Tags to trigger the release pipeline. This process automatically builds the `.deb` package.

To create a new release (Admins only):

1.  Switch to the `main` branch and pull the latest changes.
    ```bash
    git checkout main
    git pull origin main
    ```
2.  Create a tag (Semantic Versioning).
    ```bash
    git tag v1.0.0
    ```
3.  Push the tag to GitHub.
    ```bash
    git push origin v1.0.0
    ```
4.  The CI pipeline will build the package and publish it to the GitHub Releases page.

## Project Structure

- **src/**: Source code for the application.
- **tests/**: Unit tests and integration tests.
- **pyproject.toml**: Configuration file for dependencies, Ruff, Bandit, and coverage settings.
- **.github/workflows/**: CI/CD pipeline definitions.

## Troubleshooting

**Problem:** `git push` fails with an authentication error.
**Solution:** GitHub does not support password authentication. Please use a Personal Access Token (PAT) with `repo` scope as your password.

**Problem:** CI fails on "Branch out of date".
**Solution:** In the Pull Request page, click "Update branch" to merge the latest changes from the target branch into your feature branch, then wait for the checks to run again.
