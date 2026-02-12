# SOC AI Tool v2.0 - Multi-Agent Architecture

An AI-powered Security Operations Center (SOC) tool built with Google ADK (Agent Development Kit) using a hierarchical multi-agent architecture.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    FastAPI Backend                              │
│                                                                  │
│   POST /api/v1/agent  →  Orchestrator Agent                     │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                 SOC_AGENT (Orchestrator)                        │
│   "Senior SOC manager that delegates to specialists"            │
│                                                                  │
│   AgentTools: [triage, chat, action, training]                  │
└────────┬──────────┬──────────┬──────────┬───────────────────────┘
         │          │          │          │
    ┌────▼────┐ ┌───▼───┐ ┌────▼────┐ ┌───▼──────┐
    │ TRIAGE  │ │ CHAT  │ │ ACTION  │ │ TRAINING │
    │ AGENT   │ │ AGENT │ │ AGENT   │ │ AGENT    │
    │         │ │       │ │         │ │          │
    │Analyzes │ │Answers│ │Executes │ │Generates │
    │alerts,  │ │security│ │response│ │learning  │
    │creates  │ │questions│ │actions │ │content  │
    │incidents│ │        │ │         │ │& quizzes│
    └─────────┘ └────────┘ └─────────┘ └──────────┘
```

## Features

- **Multi-Agent System**: Orchestrator delegates to specialized agents
- **Alert Triage**: AI analyzes and correlates security alerts into incidents
- **Chat Interface**: Ask questions about your security data
- **Action Management**: Generate and execute response actions
- **Training Mode**: Educational content with MITRE ATT&CK mappings
- **Vector Search**: ChromaDB for semantic alert/incident search
- **Time Estimation**: Track time saved vs manual analysis

## Project Structure

```
soc_adk_tool/
├── backend/
│   ├── main.py                 # FastAPI server
│   ├── database.py             # SQLAlchemy models
│   ├── vector_store.py         # ChromaDB integration
│   ├── requirements.txt        # Python dependencies
│   ├── .env.example            # Environment template
│   │
│   ├── soc_agent/              # Agent package
│   │   ├── __init__.py         # Runner & exports
│   │   ├── agent.py            # Orchestrator agent
│   │   │
│   │   ├── triage_agent/       # Alert analysis specialist
│   │   ├── chat_agent/         # Q&A specialist
│   │   ├── action_agent/       # Response specialist
│   │   └── training_agent/     # Training specialist
│   │
│   └── shared/                 # Shared utilities
│
├── frontend/
│   ├── index.html
│   ├── script.js
│   └── styles.css
│
└── data/
    └── sample_alerts.csv       # Demo data
```

## Setup

### 1. Install Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY
```

### 3. Run the Server

```bash
cd backend
python -m uvicorn main:app --reload --port 8080
```

### 4. Access the Application

Open http://localhost:8080 in your browser.

## API Endpoints

### Main Agent Endpoint

All AI interactions go through a single endpoint:

```bash
POST /api/v1/agent
Content-Type: application/json

{
    "message": "Analyze all alerts and create incidents",
    "session_id": "optional-for-continuity"
}
```

### Example Messages

| Message | Routed To |
|---------|-----------|
| "Analyze all alerts" | triage_agent |
| "Analyze with training explanations" | triage_agent → training_agent |
| "What IPs are attacking us?" | chat_agent |
| "Execute action 5" | action_agent |
| "How many critical alerts?" | chat_agent |

### Data Endpoints (No AI)

- `GET /api/v1/alerts` - List alerts
- `GET /api/v1/incidents` - List incidents
- `GET /api/v1/incidents/{id}` - Get incident details
- `PATCH /api/v1/incidents/{id}` - Update incident
- `GET /api/v1/metrics/dashboard` - Dashboard stats
- `POST /api/v1/alerts/upload` - Upload alerts
- `DELETE /api/v1/data/reset` - Reset all data

## Agent Details

### Triage Agent
- Analyzes alerts for patterns and correlations
- Groups related alerts into incidents
- Assesses severity and attack stage
- Generates response recommendations
- Calculates time savings

### Chat Agent
- Answers questions about alerts and incidents
- Searches using semantic vector search
- Provides statistics and summaries
- Supports IP and user-based queries

### Action Agent
- Executes recommended actions
- Generates new action recommendations
- Tracks action status

### Training Agent
- Generates correlation reasoning
- Maps to MITRE ATT&CK techniques
- Creates quiz questions
- Explains severity decisions

## Requirements

- Python 3.11+
- Google Gemini API key
- 4GB RAM minimum

## Technologies

- **Backend**: FastAPI, SQLAlchemy, ChromaDB
- **AI**: Google ADK, Gemini 2.0 Flash
- **Frontend**: Vanilla JS, CSS Grid/Flexbox
- **Database**: SQLite (alerts, incidents, actions)
- **Vector DB**: ChromaDB (semantic search)
