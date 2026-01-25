# DDoS MarTumMai Detection System

This repository contains the source code for the Machine Learning-based DDoS attack detection system. This document serves as a guide for the development team to set up the environment, contribute code, and understand the project workflow.

## Prerequisites

Before setting up the project, ensure that you have the following installed on your local machine:

* **Python 3.13** or higher
* **Git** (for version control)
* **uv** (An extremely fast Python package installer and resolver)

To install `uv`, you can follow this : [Uv Installation Document](https://docs.astral.sh/uv/getting-started/installation/#standalone-installer)

## Installation and Setup

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
    
2.  **Run the application:**
    To start the detection system, use the following command:
    ```bash
    uv run ddos-martummai
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
* **main**: The production-ready branch. Contains only stable, tested code.
* **dev**: The integration branch. Features are merged here first for integration testing.

### Workflow Steps
1.  **Create a Feature Branch**: Always create a new branch from `dev`.
    ```bash
    git checkout -b feature/your-feature-name
    ```
2.  **Develop and Test**: Write your code and ensure `uv run pytest` passes locally.
3.  **Push and Open PR**: Push your branch to GitHub and open a Pull Request targeting `dev` (or `main` for hotfixes).
4.  **CI/CD Checks**: The GitHub Actions pipeline will automatically run. It checks:
    * Code Formatting (Ruff)
    * Linting (Ruff)
    * Security (Bandit)
    * Unit Tests (Pytest)
5.  **Update Branch**: If the target branch has changed, you must update your branch and ensure tests still pass.
    * *GitHub may block the merge if your branch is out of date.*
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

* **src/**: Source code for the application.
* **tests/**: Unit tests and integration tests.
* **pyproject.toml**: Configuration file for dependencies, Ruff, Bandit, and coverage settings.
* **.github/workflows/**: CI/CD pipeline definitions.

## Troubleshooting

**Problem:** `git push` fails with an authentication error.
**Solution:** GitHub does not support password authentication. Please use a Personal Access Token (PAT) with `repo` scope as your password.

**Problem:** CI fails on "Branch out of date".
**Solution:** In the Pull Request page, click "Update branch" to merge the latest changes from the target branch into your feature branch, then wait for the checks to run again.


