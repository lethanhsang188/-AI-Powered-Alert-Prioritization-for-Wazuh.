# 🚨 AI-Powered Alert Prioritization for Wazuh

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.12+-green.svg)](https://wazuh.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Enterprise-grade security alert processing pipeline** that intelligently prioritizes, correlates, and analyzes Wazuh alerts using heuristic scoring, LLM-based triage, and advanced attack detection capabilities.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Advanced Features](#advanced-features)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

**AI-Powered Alert Prioritization for Wazuh** is a SOC-grade security alert processing system designed to:

- **Eliminate alert fatigue** by intelligently filtering and prioritizing alerts
- **Detect multi-stage attacks** through supply chain attack detection
- **Normalize attack types** for consistent scoring across different agents and rule IDs
- **Provide real-time processing** with minimal latency (8-48 seconds)
- **Integrate with SOC workflows** via Telegram notifications and webhooks

The pipeline processes alerts from Wazuh Manager/Indexer, applies three-tier filtering, correlates related alerts, performs heuristic and LLM-based analysis, and delivers prioritized alerts to security teams.

---

## ✨ Key Features

### 🔍 **Three-Tier Filtering System**
- **Tier 1**: Custom rules (level 3-7) with specific rule IDs
- **Tier 2**: High-level alerts (level ≥7) for AI re-evaluation
- **Tier 3**: Attack indicators from fields (category, signature, event_type) - **ensures no real attacks are missed**

### 🔗 **Supply Chain Attack Detection**
- Automatically detects multi-stage attacks from the same source
- Groups related attacks (e.g., XSS → SQL Injection) into campaigns
- Provides severity assessment (High/Medium/Low) based on attack types
- Always notifies on supply chain attacks regardless of score

### 🎯 **Attack Type Normalization**
- Normalizes attack types (XSS, SQL Injection, CSRF, etc.) from multiple sources
- Ensures consistent scoring across different agents (WebServer vs pfSense)
- Works with different rule IDs for the same attack type

### 📊 **Intelligent Scoring**
- **Heuristic scoring**: Rule-based scoring with attack type bonuses
- **LLM analysis**: Optional GPT-based contextual analysis
- **Fused triage**: Combines heuristic and LLM scores with dynamic weighting
- **Supply chain bonus**: Additional scoring boost for multi-stage attacks

### 🔄 **Real-Time Processing**
- Dynamic lookback calculation (poll interval + indexer delay + buffer)
- Configurable polling interval (default: 8 seconds)
- Real-time mode for high-volume environments
- Agent-balanced fetching (Agent 001 and Agent 002)

### 📱 **SOC-Grade Notifications**
- **Telegram integration**: Rich, formatted alerts with full context
- **Supply chain warnings**: Prominent display of multi-stage attacks
- **IOC extraction**: Source IP, destination IP, domain, URL
- **Evidence preservation**: Full alert data for investigation

### 🛡️ **Security Features**
- PII redaction before LLM processing
- False positive detection and labeling (without dropping alerts)
- Deduplication to prevent duplicate cases
- Correlation engine for attack pattern detection

---

## 🏗️ Architecture

```
┌─────────────────┐
│  Wazuh Manager  │
│   & Indexer     │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│                    Collector Layer                       │
│  • Three-Tier Filtering (Tier 1, 2, 3)                  │
│  • Agent Balancing (001, 002)                           │
│  • Alert Normalization                                   │
│  • Field-Based Filtering                                 │
└────────┬────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│                  Analysis Layer                          │
│  ┌──────────────────┐  ┌──────────────────┐            │
│  │ Attack Type      │  │ Correlation      │            │
│  │ Normalization    │  │ Engine           │            │
│  │                  │  │ • Source Campaign│            │
│  │ • XSS            │  │ • Supply Chain   │            │
│  │ • SQL Injection  │  │   Detection      │            │
│  │ • CSRF           │  │                  │            │
│  └──────────────────┘  └──────────────────┘            │
│                                                          │
│  ┌──────────────────┐  ┌──────────────────┐            │
│  │ Heuristic        │  │ LLM Analysis    │            │
│  │ Scoring          │  │ (Optional)       │            │
│  │ • Rule level     │  │ • GPT-4/5        │            │
│  │ • Attack type    │  │ • Context-aware  │            │
│  │ • Supply chain   │  │ • PII redaction  │            │
│  └──────────────────┘  └──────────────────┘            │
│                                                          │
│  ┌──────────────────────────────────────────┐         │
│  │         Fused Triage                      │         │
│  │  • Dynamic weighting                      │         │
│  │  • Threat level adjustment                │         │
│  │  • Final score calculation                │         │
│  └──────────────────────────────────────────┘         │
└────────┬────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│                Orchestration Layer                       │
│  • Deduplication                                        │
│  • FP Labeling (without dropping)                        │
│  • Alert Card Generation                                │
│  • Notification Routing                                  │
└────────┬────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────┐      ┌─────────────────┐
│   Telegram      │      │   Webhooks      │
│  Notifications   │      │   (n8n, etc.)   │
└─────────────────┘      └─────────────────┘
```

---

## 🚀 Installation

### Prerequisites

- **Python 3.11+**
- **Wazuh Manager 4.12+** with API access
- **Wazuh Indexer** (OpenSearch/Elasticsearch) access
- **OpenAI API key** (optional, for LLM analysis)
- **Telegram Bot Token** (optional, for notifications)

### Quick Start

1. **Clone the repository:**
```bash
git clone https://github.com/lethanhsang188/-AI-Powered-Alert-Prioritization-for-Wazuh..git
cd -AI-Powered-Alert-Prioritization-for-Wazuh.
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Configure environment:**
```bash
cp env.template .env
# Edit .env with your configuration
```

4. **Run the pipeline:**
```bash
python bin/run_pipeline.py
```

### Docker Installation

```bash
# Build image
docker build -t ai-apw .

# Run with environment file
docker run --env-file .env -v $(pwd)/state:/app/state ai-apw
```

### Docker Compose

```bash
docker-compose up -d pipeline
docker-compose up -d api
```

---

## ⚙️ Configuration

### Environment Variables

**Wazuh Configuration:**
```bash
# Wazuh API
WAZUH_API_URL=https://wazuh-manager:55000
WAZUH_API_USER=wazuh
WAZUH_API_PASS=your_password
# or
WAZUH_API_TOKEN=your_token

# Wazuh Indexer
WAZUH_INDEXER_URL=https://wazuh-indexer:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=your_password

# Filtering Configuration
MIN_LEVEL=3                    # Minimum rule level (Tier 1)
MAX_LEVEL=7                    # Maximum rule level (Tier 1)
INCLUDE_RULE_IDS=100100,86601  # Comma-separated rule IDs to include
INCLUDE_RULE_ID_PREFIX=1001    # Rule ID prefix (e.g., 1001*)
ALWAYS_REEVALUATE_LEVEL_GTE=7  # Always include level >= 7 (Tier 2)

# Real-Time Processing
WAZUH_POLL_INTERVAL_SEC=8      # Poll interval (seconds)
WAZUH_START_FROM_NOW=true      # Real-time mode (recommended)
WAZUH_REALTIME_MODE=true        # Enable real-time processing
```

**LLM Configuration (Optional):**
```bash
LLM_ENABLE=true
OPENAI_API_KEY=sk-proj-...
OPENAI_API_BASE=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini           # or gpt-4, gpt-5.2, etc.
```

**Triage Configuration:**
```bash
HEURISTIC_WEIGHT=0.6            # Heuristic score weight
LLM_WEIGHT=0.4                  # LLM score weight
TRIAGE_THRESHOLD=0.70           # Minimum score to notify
```

**Telegram Configuration (Optional):**
```bash
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
```

**Correlation Configuration:**
```bash
CORRELATION_ENABLE=true
CORRELATION_TIME_WINDOW_MINUTES=15  # Time window for correlation
LOOKBACK_MINUTES_CORRELATION=30      # Lookback for correlation
DEDUP_WINDOW_MINUTES=10              # Deduplication window
```

**General:**
```bash
LOCAL_TIMEZONE=Asia/Ho_Chi_Minh
CURSOR_PATH=/app/state/cursor.json
```

See `env.template` for complete configuration options.

---

## 📖 Usage

### Basic Usage

```bash
# Run pipeline
python bin/run_pipeline.py

# Run with custom log level
LOG_LEVEL=DEBUG python bin/run_pipeline.py
```

### Real-Time Mode

Enable real-time processing for high-volume environments:

```bash
# In .env file
WAZUH_REALTIME_MODE=true
WAZUH_START_FROM_NOW=true
WAZUH_POLL_INTERVAL_SEC=8
```

**Features:**
- Dynamic lookback calculation (covers indexer delay)
- Agent-balanced fetching
- Real-time alert processing
- Minimal latency (8-48 seconds)

### API Service

Run the Flask API service (separate terminal):

```bash
python -m flask --app src.api.app run --host=0.0.0.0 --port=8088
```

**Endpoints:**
- `GET /healthz` - Liveness probe
- `GET /readyz` - Readiness probe
- `GET /` - Service info

---

## 🔬 Advanced Features

### Three-Tier Filtering

**Tier 1: Custom Rules**
- Includes alerts with level 3-7 AND matching rule IDs/prefixes
- Example: Rule 100100 (custom rule) with level 5

**Tier 2: High-Level Alerts**
- Always includes alerts with level ≥ 7
- Ensures critical alerts are never missed

**Tier 3: Attack Indicators**
- Detects attacks from fields/content, not just rule IDs
- Checks:
  - Attack categories (Web Application Attack, Exploit, Malware, etc.)
  - Attack keywords in signature (XSS, SQL Injection, CSRF, etc.)
  - Suricata event type (alert)
- **Example**: XSS attack from rule 86601 (level 3) will be included via Tier 3

### Supply Chain Attack Detection

Automatically detects when an attacker performs multiple attack types from the same source:

**Example Scenario:**
```
T+0s:   Attacker sends 10 XSS payloads from 1.2.3.4
T+60s:  Attacker switches to SQL injection (sqlmap) from 1.2.3.4
Result: Supply chain attack detected!
        - Attack types: ["xss", "sql_injection"]
        - Severity: HIGH
        - Always notified
```

**Features:**
- Groups all attacks from same source IP (source_campaign correlation)
- Detects 2+ different attack types
- Severity assessment (High/Medium/Low)
- Always notifies regardless of score

### Attack Type Normalization

Ensures consistent identification and scoring of the same attack type across different agents and rule IDs:

**Example:**
- Agent 001: Rule 31105 "XSS attempt" → normalized: `"xss"`
- Agent 002: Rule 86601 "Suricata: Alert - [L2-Exploit][XSS]" → normalized: `"xss"`
- **Result**: Both get the same attack type bonus in heuristic scoring

**Supported Attack Types:**
- `xss` - Cross-Site Scripting
- `sql_injection` - SQL Injection
- `csrf` - Cross-Site Request Forgery
- `command_injection` - Command Injection
- `path_traversal` - Path Traversal
- `web_attack` - Generic web attack

### Correlation Engine

Groups related alerts to identify attack patterns:

**Correlation Types:**
1. **source_campaign** - All attacks from same source (for supply chain detection)
2. **source_attack** - Same source IP + same attack type
3. **destination_attack** - Same destination + same attack type
4. **signature** - Same signature + time window
5. **rule_pattern** - Same rule pattern + time window

**Time Window:** Configurable (default: 15 minutes)

### Heuristic Scoring

Multi-factor scoring system:

**Base Score:**
- Rule level (non-linear curve)
- Attack type priority bonus
- Attack tool detection (sqlmap, nmap, etc.)
- Correlation bonus (campaign size)
- Supply chain bonus (severity-based)

**Attack Type Bonus:**
- XSS: +0.10
- SQL Injection: +0.10
- CSRF: +0.06
- Command Injection: +0.10

**Supply Chain Bonus:**
- High severity: +0.25
- Medium severity: +0.15
- Low severity: +0.10

### LLM Analysis

Optional GPT-based analysis for contextual understanding:

**Features:**
- Context-aware threat assessment
- Attack pattern recognition
- False positive detection
- Remediation suggestions
- PII redaction before processing

**Models Supported:**
- GPT-4o-mini (default)
- GPT-4
- GPT-5.2
- Custom OpenAI-compatible APIs

---

## 📚 Documentation

### Comprehensive Guides

- **[SOC Implementation Guide](SOC_IMPLEMENTATION_GUIDE.md)** - Complete SOC-grade implementation guide
- **[Supply Chain Attack Detection](SUPPLY_CHAIN_ATTACK_IMPLEMENTATION.md)** - Supply chain attack detection details
- **[Attack Type Normalization](ATTACK_TYPE_NORMALIZATION_IMPLEMENTATION.md)** - Attack type normalization guide
- **[Tier 3 Attack Detection](TIER_3_ATTACK_DETECTION_FROM_FIELDS.md)** - Tier 3 filtering details
- **[CSRF Detection](CSRF_DETECTION_ANALYSIS.md)** - CSRF detection and filtering

### Architecture Documentation

- **[SOC Pipeline Architecture](SOC_PIPELINE_ARCHITECTURE_DETAILED.md)** - Detailed architecture documentation
- **[SOC Architecture Summary](SOC_ARCHITECTURE_SUMMARY.md)** - Architecture overview

### Analysis & Troubleshooting

- **[Agent Balancing](AGENT_BALANCING_AND_FIELD_FETCHING_VERIFICATION.md)** - Agent balancing verification
- **[Field-Based Analysis](FIELD_BASED_ANALYSIS_IMPLEMENTATION.md)** - Field-based filtering implementation
- **[Real-Time Processing](REALTIME_PIPELINE_SOLUTION.md)** - Real-time processing solution

---

## 🧪 Testing

### Unit Tests

```bash
# Run all tests
python -m pytest tests/

# Run specific test file
python -m pytest tests/test_heuristic.py

# Run with coverage
python -m pytest tests/ --cov=src
```

### Test Files

- `tests/test_heuristic.py` - Heuristic scoring tests
- `tests/test_dedup.py` - Deduplication tests
- `tests/test_redaction.py` - PII redaction tests
- `tests/test_wazuh_client.py` - Wazuh client tests
- `tests/e2e/test_pipeline_e2e.py` - End-to-end pipeline tests

---

## 📁 Project Structure

```
.
├── bin/                          # Executable scripts
│   ├── run_pipeline.py          # Main pipeline loop
│   ├── reset_cursor.py          # Reset cursor state
│   └── test_telegram.py          # Telegram testing
├── src/
│   ├── api/                     # Flask API service
│   │   └── app.py
│   ├── collector/               # Alert collection
│   │   └── wazuh_client.py      # Wazuh API/Indexer client
│   ├── analyzer/                # Alert analysis
│   │   ├── heuristic.py         # Heuristic scoring
│   │   ├── llm.py               # LLM analysis
│   │   └── triage.py            # Fused triage
│   ├── orchestrator/             # Orchestration
│   │   └── notify.py            # Telegram/webhook notifications
│   └── common/                  # Common utilities
│       ├── attack_type_normalizer.py  # Attack type normalization
│       ├── correlation.py       # Correlation engine
│       ├── enrichment.py        # Alert enrichment
│       ├── fp_filtering.py      # False positive detection
│       ├── dedup.py             # Deduplication
│       ├── redaction.py         # PII redaction
│       └── ...
├── tests/                        # Test suite
├── configs/                      # Configuration files
│   └── wazuh/                   # Wazuh configurations
├── sample_alerts/                # Sample alert data
├── state/                        # State files (cursor, etc.)
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── env.template                  # Environment template
└── README.md
```

---

## 🔧 Configuration Examples

### Example 1: Basic Setup

```bash
# .env
WAZUH_API_URL=https://wazuh-manager:55000
WAZUH_API_USER=wazuh
WAZUH_API_PASS=password
WAZUH_INDEXER_URL=https://wazuh-indexer:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=password
MIN_LEVEL=3
MAX_LEVEL=7
ALWAYS_REEVALUATE_LEVEL_GTE=7
```

### Example 2: With LLM and Telegram

```bash
# .env
# ... Wazuh config ...

# LLM
LLM_ENABLE=true
OPENAI_API_KEY=sk-proj-...
LLM_MODEL=gpt-4o-mini

# Telegram
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# Triage
HEURISTIC_WEIGHT=0.6
LLM_WEIGHT=0.4
TRIAGE_THRESHOLD=0.70
```

### Example 3: Real-Time High-Volume

```bash
# .env
# ... Wazuh config ...

# Real-Time
WAZUH_REALTIME_MODE=true
WAZUH_START_FROM_NOW=true
WAZUH_POLL_INTERVAL_SEC=5  # Faster polling

# Correlation
CORRELATION_TIME_WINDOW_MINUTES=15
LOOKBACK_MINUTES_CORRELATION=30
```

---

## 🎯 Use Cases

### SOC Operations
- **Alert Prioritization**: Focus on high-priority alerts
- **Supply Chain Detection**: Identify multi-stage attacks
- **False Positive Reduction**: Label FPs without dropping alerts
- **Real-Time Monitoring**: Process alerts in near real-time

### Security Analysis
- **Attack Pattern Recognition**: Correlate related attacks
- **Attack Type Normalization**: Consistent identification across agents
- **Contextual Analysis**: LLM-based threat assessment
- **Evidence Preservation**: Full alert data for investigation

### Integration
- **Telegram Notifications**: Rich, formatted alerts
- **Webhook Integration**: n8n, SOAR platforms
- **API Service**: Health checks, service info
- **Custom Integrations**: Extensible notification system

---

## 🔒 Security Considerations

### Data Protection
- **PII Redaction**: Automatic redaction before LLM processing
- **Secure Storage**: Environment variables for sensitive data
- **SSL Verification**: Configurable SSL certificate verification
- **Token Management**: Secure API token handling

### Best Practices
- Never commit `.env` file (already in `.gitignore`)
- Use strong passwords for Wazuh API/Indexer
- Rotate API keys regularly
- Monitor pipeline logs for anomalies
- Review false positive labels regularly

---

## 📊 Performance

### Throughput
- **Standard Mode**: 8-second polling interval
- **Real-Time Mode**: 1-5 second polling interval
- **Processing Time**: <1 second per alert
- **Total Latency**: 8-48 seconds (includes indexer delay)

### Resource Usage
- **CPU**: Low to moderate (depends on LLM usage)
- **Memory**: ~100-500 MB (depends on batch size)
- **Network**: Moderate (API calls to Wazuh, OpenAI, Telegram)

---

## 🐛 Troubleshooting

### Common Issues

**1. No alerts being fetched:**
- Check Wazuh API/Indexer connectivity
- Verify credentials in `.env`
- Check rule level filters (MIN_LEVEL, MAX_LEVEL)
- Enable Tier 3 filtering for low-level attacks

**2. Alerts being filtered:**
- Check field-based filtering logic
- Verify attack indicators (category, signature, event_type)
- Review filtering logs for reasons

**3. Supply chain not detected:**
- Verify correlation is enabled
- Check time window (CORRELATION_TIME_WINDOW_MINUTES)
- Ensure multiple attack types from same source

**4. Telegram not sending:**
- Verify TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID
- Check message formatting (Markdown validation)
- Review notification logs

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes**
4. **Add tests** for new features
5. **Update documentation** as needed
6. **Commit your changes**: `git commit -m 'Add amazing feature'`
7. **Push to the branch**: `git push origin feature/amazing-feature`
8. **Open a Pull Request**

### Development Setup

```bash
# Clone repository
git clone https://github.com/lethanhsang188/-AI-Powered-Alert-Prioritization-for-Wazuh..git
cd -AI-Powered-Alert-Prioritization-for-Wazuh.

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run tests
python -m pytest tests/
```

---

## 📝 Changelog

### Version 2.0 (2025-12-17)

**Major Features:**
- ✨ Supply chain attack detection
- ✨ Attack type normalization
- ✨ Three-tier filtering (Tier 3: attack indicators from fields)
- ✨ CSRF detection and filtering
- ✨ Source campaign correlation
- ✨ Enhanced Telegram notifications with supply chain warnings
- ✨ Improved heuristic scoring with attack type bonuses

**Improvements:**
- 🔧 Field-based filtering improvements (severity conversion, category/signature checks)
- 🔧 Agent balancing verification
- 🔧 Real-time processing optimizations
- 🔧 Documentation updates

See individual feature documentation for details.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Wazuh** - Open-source security monitoring platform
- **OpenAI** - GPT models for LLM analysis
- **Telegram** - Notification platform

---

## 📧 Support

For issues, questions, or contributions:
- **GitHub Issues**: [Create an issue](https://github.com/lethanhsang188/-AI-Powered-Alert-Prioritization-for-Wazuh./issues)
- **Documentation**: See [SOC_IMPLEMENTATION_GUIDE.md](SOC_IMPLEMENTATION_GUIDE.md)

---

## ⭐ Star History

If you find this project useful, please consider giving it a star! ⭐

---

**Built with ❤️ for SOC teams**
