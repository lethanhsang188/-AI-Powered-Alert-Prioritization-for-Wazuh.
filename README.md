# AI-APW: AI-Powered Alert Prioritization for Wazuh

Automated security alert processing pipeline that collects alerts from Wazuh, analyzes them using heuristic and optional LLM-based triage, and creates cases in TheHive.

## Features

- **Alert Collection**: Fetches alerts from Wazuh 4.14.0 API with cursor-based pagination
- **Heuristic Analysis**: Rule-based scoring based on alert level and rule groups
- **LLM Analysis**: Optional OpenAI GPT-based analysis for alert context
- **Fused Triage**: Combines heuristic and LLM scores with configurable weights
- **Deduplication**: Deterministic key generation to prevent duplicate cases
- **PII Redaction**: Automatic redaction of sensitive data before LLM processing
- **TheHive Integration**: Creates and updates cases in TheHive with severity mapping
- **n8n Notifications**: Optional webhook notifications for high-severity cases
- **Health Checks**: `/healthz` and `/readyz` endpoints for Kubernetes

## Architecture

```
Wazuh API → Collector → Analyzer → Orchestrator → TheHive
                              ↓
                            LLM (optional)
                              ↓
                            n8n (optional)
```

## Quick Start

### Prerequisites

- Python 3.11+
- Docker & Docker Compose (optional)
- Wazuh Manager 4.14.0+ with API access
- TheHive instance with API key
- OpenAI API key (optional, for LLM analysis)
- n8n webhook URL (optional)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/lethanhsang188/ai-apw.git
cd ai-apw
```

2. Copy and configure environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

### Configuration

Edit `.env` file with your settings:

```bash
# Wazuh Configuration
WAZUH_API_URL=http://wazuh-manager:55000
WAZUH_API_USER=wazuh
WAZUH_API_PASS=your_password
# or
WAZUH_API_TOKEN=your_token
WAZUH_MIN_LEVEL=7
WAZUH_POLL_INTERVAL_SEC=8

# TheHive Configuration
THEHIVE_URL=http://thehive:9000
THEHIVE_API_KEY=your_api_key

# LLM Configuration (optional)
LLM_ENABLE=false
OPENAI_API_KEY=your_openai_key
OPENAI_API_BASE=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini

# Triage Weights
HEURISTIC_WEIGHT=0.6
LLM_WEIGHT=0.4
TRIAGE_THRESHOLD=0.70

# n8n Configuration (optional)
N8N_WEBHOOK_URL=http://n8n:5678/webhook/alert
```

### Running

#### Local Development

```bash
# Run pipeline
python bin/run_pipeline.py

# Run API service (separate terminal)
python -m flask --app src.api.app run --host=0.0.0.0 --port=8088
```

#### Docker Compose

```bash
docker-compose up -d pipeline
docker-compose up -d api
```

#### Docker

```bash
docker build -t ai-apw .
docker run --env-file .env -v $(pwd)/state:/app/state ai-apw
```

## Pipeline Flow

1. **Collection**: Fetches alerts from Wazuh API using cursor-based pagination
2. **Deduplication**: Generates deterministic key (rule_id:agent_id:srcip:day)
3. **Triage**:
   - Heuristic score: `rule.level / 15.0` (with bonus for high-severity groups)
   - LLM score: Optional GPT-based analysis (with PII redaction)
   - Final score: `HEURISTIC_WEIGHT * heuristic + LLM_WEIGHT * llm`
4. **Orchestration**:
   - Search for existing case by dedup key
   - Create new case if not found (severity mapped from score)
   - Update existing case with new alert if found
5. **Notification**: Send webhook to n8n if score >= 0.7

## Severity Mapping

- Score >= 0.85 → Critical (4)
- Score >= 0.70 → High (3)
- Score < 0.70 → Medium (2)

## API Endpoints

- `GET /healthz` - Liveness probe
- `GET /readyz` - Readiness probe
- `GET /` - Service info

## Testing

Run unit tests:

```bash
python -m pytest tests/
# or
python -m unittest discover tests
```

## Project Structure

```
.
├── bin/
│   └── run_pipeline.py       # Main pipeline loop
├── src/
│   ├── api/
│   │   └── app.py            # Flask API service
│   ├── collector/
│   │   └── wazuh_client.py   # Wazuh API client
│   ├── analyzer/
│   │   ├── heuristic.py      # Heuristic scoring
│   │   ├── llm.py            # LLM analysis
│   │   └── triage.py         # Fused triage
│   ├── orchestrator/
│   │   ├── thehive_client.py # TheHive API client
│   │   └── notify.py         # n8n notification
│   └── common/
│       ├── config.py         # Configuration loading
│       ├── logging.py        # JSON logging
│       ├── dedup.py          # Deduplication
│       ├── redaction.py      # PII redaction
│       └── web.py            # HTTP client
├── tests/
│   ├── test_dedup.py
│   ├── test_heuristic.py
│   └── test_redaction.py
├── sample_alerts/
│   └── sample_alert.json
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## State Management

The pipeline maintains cursor state in `/app/state/cursor.json` (configurable via `CURSOR_PATH`) to track the last processed alert timestamp.

## Logging

All logs are in JSON format for easy parsing and aggregation:

```json
{"level": "INFO", "ts": "2024-01-15T10:30:00Z", "msg": "Processing 5 alerts", "logger": "root"}
```

## License

MIT License (see LICENSE file)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

