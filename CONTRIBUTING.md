# Contributing to FileGuard

Thank you for your interest in contributing to FileGuard! This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and inclusive
- Report security issues privately to mayur.nhavalde@gmail.com
- No harassment or discrimination

## Getting Started

1. **Fork the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/FileGuard.git
   cd FileGuard
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Set up development environment**
   ```bash
   docker-compose up -d
   pip install -r api/requirements.txt
   ```

4. **Make your changes**
   - Write clean, documented code
   - Follow PEP 8 style guide
   - Add tests for new features

5. **Test your changes**
   ```bash
   pytest tests/ -v
   ```

6. **Commit and push**
   ```bash
   git add .
   git commit -m "feat: add your feature"
   git push origin feature/your-feature-name
   ```

7. **Create Pull Request**
   - Provide clear description
   - Link related issues
   - Ensure tests pass

## Commit Message Format

```
type: subject

body

Fixes #123
```

Types: feat, fix, docs, style, refactor, test, chore

## Code Style

- Python: PEP 8 (use `flake8`)
- Max line length: 100 characters
- Use type hints
- Document functions with docstrings

## Testing

- All tests must pass
- Maintain >80% code coverage
- Add tests for new features
- Run: `pytest tests/ --cov=api`

## Documentation

- Update README.md if needed
- Add docstrings to functions
- Document API changes

## Pull Request Process

1. Update documentation
2. Add tests
3. Update CHANGELOG.md
4. Pass CI/CD checks
5. Request review

## Reporting Issues

Use GitHub Issues with:
- Clear title
- Detailed description
- Steps to reproduce
- Expected vs actual behavior
- Environment info

## Questions?

Open a discussion or email mayur.nhavalde@gmail.com

Thank you for contributing! 🎉
