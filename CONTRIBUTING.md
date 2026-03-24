# Contributing to jawt

First off, thank you for considering contributing to `jawt`! It's people like you that make it a great tool.

## 🛠 Development Setup

1.  **Fork the repository** on GitHub.
2.  **Clone your fork** locally:
    ```bash
    git clone https://github.com/YOUR_USERNAME/jawt.git
    cd jawt
    ```
3.  **Install dependencies**:
    ```bash
    go mod download
    ```
4.  **Run tests** to ensure everything is working:
    ```bash
    go test ./...
    ```

## 📜 Contribution Guidelines

- **Small PRs**: We prefer small, focused Pull Requests that do one thing well.
- **Tests**: Every new feature or bug fix must include corresponding tests.
- **Documentation**: Update `README.md` and `GEMINI.md` if your changes affect the CLI interface or architecture.
- **Commit Messages**: Use clear, descriptive commit messages (e.g., `verifier: add support for PS256`).

## 🚀 Pull Request Process

1.  Create a new branch for your feature or fix: `git checkout -b feature/my-new-feature`.
2.  Commit your changes.
3.  Push to your fork and submit a Pull Request.
4.  Ensure CI passes. We will review it as soon as possible!

## ⚖️ License

By contributing, you agree that your contributions will be licensed under its MIT License.
