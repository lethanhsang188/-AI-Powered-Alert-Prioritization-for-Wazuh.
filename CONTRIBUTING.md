# Contributing to AI-Powered Alert Prioritization for Wazuh

Thank you for your interest in contributing to this project! We welcome contributions from the community.

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- Git
- Familiarity with security monitoring and Wazuh

### Development Setup
```bash
# Fork the repository
git clone https://github.com/your-username/-AI-Powered-Alert-Prioritization-for-Wazuh..git
cd -AI-Powered-Alert-Prioritization-for-Wazuh.

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies

# Run tests
python -m pytest tests/
```

## 📝 Contribution Guidelines

### Code Style
- Follow PEP 8 style guidelines
- Use type hints for function parameters and return values
- Write comprehensive docstrings
- Keep functions focused and modular

### Testing
- Write unit tests for new features
- Ensure all tests pass before submitting PR
- Aim for >80% code coverage
- Test edge cases and error conditions

### Documentation
- Update README.md for significant changes
- Add docstrings to all public functions
- Update configuration examples if needed

## 🐛 Reporting Issues

### Bug Reports
Please include:
- Clear description of the issue
- Steps to reproduce
- Expected vs actual behavior
- Environment details (Python version, OS, Wazuh version)
- Relevant log output

### Feature Requests
Please include:
- Clear description of the proposed feature
- Use case and benefits
- Implementation approach (if applicable)

## 🔄 Pull Request Process

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/your-feature-name`
3. **Make** your changes with tests
4. **Run** the full test suite: `python -m pytest tests/`
5. **Update** documentation if needed
6. **Commit** with clear messages: `git commit -m "Add: feature description"`
7. **Push** to your fork: `git push origin feature/your-feature-name`
8. **Create** a Pull Request with detailed description

### PR Requirements
- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] No breaking changes without discussion
- [ ] PR description includes testing instructions

## 🏗️ Architecture Guidelines

### Code Organization
- Keep business logic in appropriate modules
- Use dependency injection for testability
- Follow single responsibility principle
- Maintain clear separation of concerns

### Security Considerations
- Never commit sensitive credentials
- Use environment variables for configuration
- Implement proper input validation
- Follow principle of least privilege

## 📋 Areas for Contribution

### High Priority
- [ ] Performance optimizations
- [ ] Additional threat detection rules
- [ ] Enhanced correlation algorithms
- [ ] API improvements

### Medium Priority
- [ ] Additional notification channels
- [ ] Dashboard integration
- [ ] Configuration validation
- [ ] Error handling improvements

### Future Enhancements
- [ ] Machine learning-based anomaly detection
- [ ] Integration with additional SIEM platforms
- [ ] Advanced threat hunting capabilities
- [ ] Container security integration

## 📞 Communication

- **Issues**: Use GitHub Issues for bugs and features
- **Discussions**: Use GitHub Discussions for questions
- **Security**: Report security issues privately to maintainers

## 📄 License

By contributing to this project, you agree that your contributions will be licensed under the same MIT License that covers the project.

Thank you for helping make this project better! 🎉
