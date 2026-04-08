# Feature 006 — Defender Brain Evolution

Self-improving defender brain that learns from production decisions and shows progress transparently.

## Goal

The brain starts weak (95.2% on training data, untested in production) and improves every week by learning from real AI decisions. The operator sees the evolution in the dashboard — no black box.

## Steps

### Step 1: Deploy supervised model ✅ READY
- Replace `defender-brain.bin` (538KB gym-only) with supervised model (27KB, trained on real data)
- Brain suggests actions based on real production patterns (observe/block/alert)
- Still advisory-only — AI makes the final decision

### Step 2: Weekly auto-retrain
- Every Sunday 4 AM UTC, retrain brain from brain-log.json (has 72-dim features + AI decisions)
- Use last 30 days of data (rolling window)
- Save previous model as backup before replacing
- Skip if < 100 new entries since last train
- Log: "brain retrained: accuracy X%, entries N, agreement Y%"

### Step 3: Dashboard widget — "Brain Lab"
- New card in Intelligence tab or standalone section
- Shows:
  - **Agreement rate**: current % brain agrees with AI (real-time)
  - **Weekly trend**: bar chart of agreement % over last 8 weeks
  - **Action breakdown**: what brain suggests vs what AI decides (confusion matrix)
  - **Status**: "Learning (week 1)" → "Improving (week 4)" → "Mature (week 8+)"
  - **Last trained**: timestamp + accuracy + data points used
- Label: "🧪 Experimental — Brain is learning from your server's patterns"

### Step 4: Agreement tracking in agent
- After each AI decision, compare brain suggestion with AI decision
- Track: agreed_count, total_count, rolling 7-day agreement %
- Persist to `brain-stats.json` (for dashboard + weekly trend)

### Step 5: Graduation criteria
- When agreement > 70% for 2 consecutive weeks:
  - Auto-enable "brain fast-path" for Low/Medium severity incidents
  - Brain decides without calling AI → saves tokens
  - High/Critical still goes to AI
  - Dashboard shows: "Brain is handling N% of decisions independently"

## Architecture

```
AI Decision Pipeline:
  incident → build_brain_features(72-dim)
           → brain.suggest() → log to brain-log.json (with features)
           → AI provider → final decision
           → compare brain vs AI → update brain-stats.json

Weekly retrain (cron):
  brain-log.json → extract (features, ai_action) pairs
                 → train [72→64→30] supervised
                 → export IWD1 → hot-reload

Dashboard:
  brain-stats.json → agreement %, trend chart, action breakdown
```

## Files to modify

| File | Change |
|------|--------|
| `crates/agent/src/defender_brain.rs` | Add weekly retrain, hot-reload, agreement tracking |
| `crates/agent/src/incident_decision_eval.rs` | Track agreement stats |
| `crates/agent/src/main.rs` | Weekly retrain trigger in slow loop |
| `crates/agent/src/dashboard.rs` | Brain Lab widget |
| `defender-brain.bin` | Replace with supervised model |

## Non-goals (this spec)
- Online learning (per-decision gradient updates) — too complex, weekly batch is enough
- Replacing AI for High/Critical — brain is advisory only for those
- Federated learning across mesh — future feature
