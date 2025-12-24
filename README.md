# AI-Powered Alert Prioritization for Wazuh

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.14+-green.svg)](https://wazuh.com/)

An enterprise-grade AI-powered security alert processing pipeline that intelligently prioritizes and responds to Wazuh alerts using advanced heuristic analysis and optional Large Language Model (LLM) triage.

## 🚀 Features

### Core Capabilities
- **Intelligent Alert Collection**: Automated fetching from Wazuh indexer with field normalization
- **Multi-Layer Analysis**: Combines heuristic scoring with optional LLM-based contextual analysis
- **Advanced Threat Detection**: Supply chain attack detection, attack type normalization, and correlation
- **Automated Response**: Intelligent blocking of high-confidence threats via pfSense firewall integration
- **Rich Notifications**: Formatted Telegram alerts with actionable threat intelligence

### Security Analysis
- **Heuristic Scoring**: Rule-level analysis with attack type bonuses and severity weighting
- **LLM Analysis**: GPT-powered threat assessment with false positive detection
- **Supply Chain Detection**: Multi-stage attack pattern recognition across time windows
- **Correlation Engine**: Source-based attack campaign identification
- **False Positive Filtering**: Context-aware FP reduction while preserving security signals

### Enterprise Features
- **Real-time Processing**: Sub-second alert processing with configurable polling intervals
- **Scalable Architecture**: Designed for high-volume SOC environments
- **Audit Trail**: Comprehensive logging and response tracking
- **Configurable Policies**: Flexible threat response rules and suppression windows
- **Security-First Design**: PII redaction, secure credential management, and SSL verification

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Wazuh Indexer │───▶│   Alert Collector│───▶│   AI Analyzer   │───▶│  Orchestrator   │
│   (Elasticsearch)│    │   (wazuh_client)│    │ (heuristic+LLM) │    │  (notify+AR)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │                       │
         ▼                       ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Host & Network │    │   Normalization │    │   Triage Score  │    │   Telegram +    │
│     Logs        │    │   & Enrichment  │    │   (0.0-1.0)     │    │   Auto-Response │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Key Components

| Component | Purpose | Technology |
|-----------|---------|------------|
| **Collector** | Fetches and normalizes alerts from Wazuh | Python + Elasticsearch |
| **Analyzer** | Scores alerts using heuristics and LLM | OpenAI GPT + Custom Rules |
| **Triage** | Fuses scores into actionable priorities | Weighted Algorithm |
| **Orchestrator** | Handles notifications and automated response | Telegram API + SSH |

## 📋 Requirements

- **Python**: 3.8 or higher
- **Wazuh**: 4.14+ with indexer access
- **pfSense**: For automated blocking (optional)
- **OpenAI API**: For LLM analysis (optional)
- **Telegram Bot**: For notifications (optional)

## 🚀 Quick Start

### 1. Clone and Setup
```bash
git clone https://github.com/lethanhsang188/-AI-Powered-Alert-Prioritization-for-Wazuh..git
cd -AI-Powered-Alert-Prioritization-for-Wazuh.
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment
```bash
cp .env.example .env
# Edit .env with your Wazuh credentials and settings
```

### 4. Run the Pipeline
```bash
python bin/run_pipeline.py
```

## ⚙️ Configuration

### Essential Settings
```bash
# Wazuh Connection
WAZUH_INDEXER_URL=https://wazuh-indexer:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=your_password

# Alert Processing
MIN_LEVEL=3
MAX_LEVEL=15
TRIAGE_THRESHOLD=0.7

# LLM Analysis (Optional)
LLM_ENABLE=true
OPENAI_API_KEY=sk-proj-your-key-here
LLM_MODEL=gpt-4o-mini
```

### Advanced Configuration
```bash
# Real-time Processing
WAZUH_REALTIME_MODE=true
WAZUH_POLL_INTERVAL_SEC=5

# Automated Response
ENABLE_ACTIVE_RESPONSE=true
ACTIVE_RESPONSE_REQUIRE_CONFIRM=false
FAST_BLOCK_TAGS=sql_injection,xss,web_attack

# Correlation
CORRELATION_TIME_WINDOW_MINUTES=15
SUPPLY_CHAIN_ATTACK_DETECTION=true
```

## 🔍 Threat Detection Capabilities

### Attack Types Detected
- **Web Attacks**: SQL Injection, XSS, CSRF, Command Injection
- **Authentication**: Brute Force, Failed Login Attempts
- **Network**: SYN Flood, Port Scanning, IDS Alerts
- **Supply Chain**: Multi-stage attack patterns
- **Reconnaissance**: Network scanning and enumeration

### Scoring Algorithm
```
Final Score = (Heuristic Score × Heuristic Weight) + (LLM Score × LLM Weight)

Where:
- Heuristic Score: 0.0-1.0 (based on rule level, groups, attack patterns)
- LLM Score: 0.0-1.0 (contextual threat assessment)
- Weights: Configurable (default: 0.6 heuristic, 0.4 LLM)
```

### Priority Mapping
| Triage Score | Threat Level | Priority | Action |
|--------------|--------------|----------|--------|
| 0.8-1.0 | Critical | P1 | Immediate Block + Alert |
| 0.6-0.8 | High | P2 | Fast Block + Alert |
| 0.4-0.6 | Medium | P3 | Alert Only |
| 0.0-0.4 | Low/Info | P4 | Log Only |

## 🛡️ Automated Response

### pfSense Integration
- **IP Blocking**: Automatic addition to `WAZUH_BLOCK` table
- **SSH Execution**: Secure command execution on pfSense
- **Auto-Unblock**: Configurable time-based removal
- **Audit Trail**: Complete response logging

### Response Triggers
```python
FAST_BLOCK_TAGS = [
    "sql_injection", "xss", "csrf",
    "command_injection", "lfi", "web_attack"
]
```

## 📊 Monitoring & Analytics

### Built-in API
```bash
# Health Check
curl http://localhost:5000/health

# Pipeline Status
curl http://localhost:5000/status

# Recent Alerts
curl http://localhost:5000/alerts?limit=10
```

### Logging
- **Structured Logging**: JSON format with correlation IDs
- **Multiple Levels**: DEBUG, INFO, WARNING, ERROR
- **Rotation**: Automatic log file rotation
- **Performance Metrics**: Processing times and throughput

## 🧪 Testing

### Unit Tests
```bash
# Run all tests
python -m pytest tests/

# Run with coverage
python -m pytest tests/ --cov=src --cov-report=html

# Run specific tests
python -m pytest tests/test_heuristic.py -v
```

### Integration Tests
```bash
# End-to-end pipeline test
python -m pytest tests/e2e/test_pipeline_e2e.py

# Active Response testing
python tools/test_active_response.py
```

## 📁 Project Structure

```
.
├── bin/                          # Executable scripts
│   ├── run_pipeline.py          # Main pipeline orchestrator
│   └── reset_cursor.py          # State management
├── src/
│   ├── collector/               # Alert collection layer
│   │   └── wazuh_client.py      # Wazuh API client
│   ├── analyzer/                # Analysis engines
│   │   ├── heuristic.py         # Rule-based scoring
│   │   ├── llm.py              # LLM analysis
│   │   └── triage.py           # Score fusion
│   ├── orchestrator/            # Action orchestration
│   │   ├── notify.py           # Notification handling
│   │   └── active_response.py  # Automated blocking
│   ├── api/                     # REST API service
│   └── common/                  # Shared utilities
├── tests/                       # Test suite
├── configs/                     # Configuration files
├── sample_alerts/               # Sample data
├── state/                       # Runtime state
├── docs/                        # Documentation
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## 🔐 Security Considerations

### Data Protection
- **PII Redaction**: Automatic removal of sensitive data before LLM processing
- **Secure Credentials**: Environment variable-based configuration
- **SSL Verification**: Mandatory certificate validation
- **Token Security**: Secure API key management

### Operational Security
- **Audit Logging**: Complete action traceability
- **Response Validation**: Policy-based decision making
- **Rate Limiting**: Protection against abuse
- **Error Handling**: Secure failure modes

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Fork and clone
git clone https://github.com/your-username/-AI-Powered-Alert-Prioritization-for-Wazuh..git

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Wazuh Community**: For the excellent security platform
- **OpenAI**: For powerful LLM capabilities
- **pfSense**: For robust firewall technology

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/lethanhsang188/-AI-Powered-Alert-Prioritization-for-Wazuh./issues)
- **Documentation**: See [docs/](docs/) directory
- **Discussions**: [GitHub Discussions](https://github.com/lethanhsang188/-AI-Powered-Alert-Prioritization-for-Wazuh./discussions)

---

**Built for SOC teams who demand intelligence, speed, and reliability in threat response.**
