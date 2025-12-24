# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-12-24

### Added
- **AI-Powered Alert Analysis**: Integrated GPT models for contextual threat assessment
- **Advanced Threat Detection**: Supply chain attack detection and attack type normalization
- **Automated Response**: Intelligent IP blocking via pfSense firewall integration
- **Rich Notifications**: Formatted Telegram alerts with actionable intelligence
- **Real-time Processing**: Sub-second alert analysis with configurable polling
- **Enterprise Features**: PII redaction, audit trails, and security hardening
- **Docker Support**: Containerized deployment with docker-compose
- **CI/CD Pipeline**: GitHub Actions for automated testing and deployment
- **Documentation Site**: MkDocs-powered documentation with GitHub Pages
- **Comprehensive Testing**: Unit tests, integration tests, and security scanning
- **Professional Packaging**: PyPI distribution with setup.py and pyproject.toml

### Changed
- **Architecture Overhaul**: Modular design with clear separation of concerns
- **Configuration Management**: Environment-based configuration with validation
- **Code Quality**: Comprehensive linting, type checking, and formatting
- **Documentation**: Professional README and contributing guidelines

### Technical Details
- **Python Version Support**: 3.8, 3.9, 3.10, 3.11
- **Wazuh Compatibility**: 4.14+
- **Dependencies**: Carefully selected for security and performance
- **Security**: Built-in PII redaction and secure credential handling

### Infrastructure
- **GitHub Actions**: Automated CI/CD with testing and security scanning
- **Docker Hub**: Automated image building and publishing
- **GitHub Pages**: Automated documentation deployment
- **Codecov**: Test coverage reporting and tracking

---

## [0.1.0] - 2024-01-01

### Added
- Initial proof-of-concept implementation
- Basic Wazuh alert collection and processing
- Simple heuristic scoring
- Console output for alerts

### Known Issues
- Limited scalability
- No automated response capabilities
- Basic documentation only

---

## Types of changes
- `Added` for new features
- `Changed` for changes in existing functionality
- `Deprecated` for soon-to-be removed features
- `Removed` for now removed features
- `Fixed` for any bug fixes
- `Security` in case of vulnerabilities

## Version Format
This project uses [Semantic Versioning](https://semver.org/):
- **MAJOR.MINOR.PATCH** (e.g., 1.0.0)
- **MAJOR**: Breaking changes
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, backward compatible
