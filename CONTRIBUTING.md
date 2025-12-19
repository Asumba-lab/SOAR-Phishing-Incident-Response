# Contributing to SOAR Phishing Project

Thank you for your interest in contributing to the SOAR Phishing Project! This document outlines how you can contribute to the project.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Code Style](#code-style)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Feature Requests](#feature-requests)

## Code of Conduct

This project adheres to the [Contributor Covenant](https://www.contributor-covenant.org/). By participating, you are expected to uphold this code.

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally
   ```bash
   git clone https://github.com/your-username/soar-phishing-project.git
   cd soar-phishing-project
   ```
3. **Set up the development environment**
   ```bash
   # Using poetry (recommended)
   poetry install
   
   # Or using pip
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements-dev.txt
   ```
4. **Set up pre-commit hooks**
   ```bash
   pre-commit install
   ```

## Development Workflow

1. Create a new branch for your feature or bugfix:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b bugfix/issue-number-description
   ```

2. Make your changes and commit them with a descriptive message:
   ```bash
   git commit -m "feat: add new feature"
   ```

3. Push your changes to your fork:
   ```bash
   git push origin your-branch-name
   ```

4. Open a Pull Request against the `main` branch.

## Code Style

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide
- Use type hints for all functions and methods
- Keep lines under 88 characters (Black's default)
- Use docstrings following Google style
- Run formatters and linters before committing:
  ```bash
  black .
  isort .
  flake8
  mypy .
  ```

## Testing

Run tests with:
```bash
pytest
```

Write tests for new features and bug fixes. Aim for good test coverage.

## Pull Request Process

1. Ensure all tests pass
2. Update documentation as needed
3. Ensure your code is properly formatted
4. Request review from at least one maintainer
5. Address all review feedback
6. Once approved, a maintainer will merge your PR

## Reporting Bugs

Please use GitHub Issues to report bugs. Include:
- A clear, descriptive title
- Steps to reproduce
- Expected vs. actual behavior
- Environment details
- Any relevant logs or screenshots

## Feature Requests

Open an issue with:
- A clear description of the feature
- The problem it solves
- Any alternative solutions considered
- Additional context
