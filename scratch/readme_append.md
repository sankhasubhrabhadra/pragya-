## Stage 3: Anomaly Detection
The anomaly detection engine builds normal-behavior profiles for users over the first N-1 days, and flags deviations on the final live day using explainable rules and an Isolation Forest ML model.

### Generating Logs with Decoys
To test anomaly scoring, generate logs with `--decoys` to inject benign false alarms (e.g., students mistyping passwords):
```bash
python generate_logs.py --decoys
```

### Evaluation
```bash
python evaluate_anomaly.py
```

## Stage 4: AI Investigator Agent
The agent automatically calls tools (e.g. mapping the attack path, generating a containment plan) and summarizes its findings into a final report.

### Running Modes
You can configure the agent to run in 3 different modes via the `PRAGYA_AGENT_MODE` environment variable (default is `scripted`):

#### 1. Scripted Mode (Offline / Deterministic)
This mode does not use an LLM. It simply walks through a hardcoded playbook. Perfect for fast, offline demos.
```bash
set PRAGYA_AGENT_MODE=scripted
uvicorn main:app --reload
```

#### 2. Ollama Mode (Local LLM)
Uses a local model via Ollama. 
1. Install [Ollama](https://ollama.com/).
2. Start the Ollama server and pull a model (e.g., `ollama run llama3.2`).
3. Set the mode and run:
```bash
set PRAGYA_AGENT_MODE=ollama
uvicorn main:app --reload
```

#### 3. Gemini Mode (Cloud LLM)
Uses Google's Gemini API via the free tier.
```bash
set PRAGYA_AGENT_MODE=gemini
set GEMINI_API_KEY="your_api_key_here"
uvicorn main:app --reload
```

### Endpoints
- `POST /incidents/{id}/investigate?mode=scripted` - Streams the investigation steps.
- `GET /incidents/{id}/report` - Fetches the finalized report.
- `POST /incidents/{id}/contain` - Stages containment actions (requires approval).
- `GET /agent/status` - Checks current LLM reachability.

### Evaluation
```bash
python evaluate_agent.py
```
