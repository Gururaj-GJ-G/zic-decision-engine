# API Reference

## `POST /decide`

Submit a fraud event and receive a fully explainable decision.

**Request:**
```json
{
  "event_type": "transaction",
  "account_id": "acc_12345",
  "amount": 4500,
  "context": {
    "device_id": "dev_abc",
    "velocity_flag": true
  }
}
```

**Response:**
```json
{
  "decision_id": "uuid",
  "action": "BLOCK",
  "risk_score": 88.5,
  "triggered_signals": [
    { "code": "VEL_003", "category": "VELOCITY", "weight": 0.62 },
    { "code": "MUL_001", "category": "MULE", "weight": 0.71 }
  ],
  "narrative": "Blocked due to velocity and mule-pattern signal combination.",
  "governance_version": "2.1.0"
}
```

Every field in `triggered_signals` maps directly to an entry in the 114-signal governance file,
so the decision can always be traced back to a specific, versioned rule.
