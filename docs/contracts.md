# contracts.md

## Rules

* Do not rename fields.
* Do not remove fields.
* Extensions must remain backward compatible.

## Task

```json
{
  "task_id": "string",
  "action": "string",
  "target": "string",
  "context": {},
  "priority": "low|medium|high"
}
```

## WorkerResponse

```json
{
  "status": "success|failure",
  "worker": "string",
  "task_id": "string",
  "data": {},
  "new_findings": [],
  "errors": []
}
```

## Route

```json
{
  "route_id": "string",
  "url": "string",
  "discovered_at": "datetime"
}
```

## Form

```json
{
  "action": "string",
  "method": "GET|POST|PUT|DELETE|UNKNOWN"
}
```

## ReconResult

```json
{
  "url": "string",
  "forms": [],
  "inputs": [],
  "buttons": [],
  "links": [],
  "scripts": [],
  "meta_tags": []
}
```

## Feature (Phase 3)

```json
{
  "feature_id": "string",
  "name": "string",
  "routes": [],
  "classification_confidence": 0.0,
  "analyzed": false
}
```

## Finding (Phase 6)

```json
{
  "finding_id": "string",
  "type": "string",
  "title": "string",
  "feature": "string",
  "severity": "low|medium|high|critical",
  "model_severity": "informational|low|medium|high|critical|null",
  "security_confidence": 0.0,
  "evidence": []
}
```

`model_severity` is an additive extension: the ML severity model's
(Nuclei-trained TF-IDF + linear SVM) second opinion on the finding. It
never replaces `severity`, which remains the analysis LLM's assessment.

## CoverageState

```json
{
  "authentication": {
    "discovered": false,
    "analyzed": false
  }
}
```

## SQLite

routes(url, discovered_at)

features(name, analyzed)

findings(title, severity)

tasks(action, status, created_at)

## Phase 1

Allowed:

* Playwright
* BeautifulSoup
* Route discovery
* Form extraction
* Input extraction
* Button extraction
* SQLite

Forbidden:

* LLM calls
* ChromaDB
* Feature classification
* Findings generation
* Vulnerability analysis
* Report generation

```
```
