# ZIC Decision Engine

**Status:** v2.1.0 · Independent open-source project

**Documentation:** [ARCHITECTURE.md](./ARCHITECTURE.md) · [API.md](./API.md) · [LICENSE](./LICENSE)

Maintained by **Gururaj G J** — Senior Fraud Risk | Merchant Risk | Financial Crime Professional
[LinkedIn](https://www.linkedin.com/in/gururaj-gj-52a062b4/) · [GitHub](https://github.com/Gururaj-GJ-G)

> Note: this is a separate codebase from the [Fraud Investigation Canvas](https://github.com/Gururaj-GJ-G/fraud-investigation-canvas) —
> same product family, distinct functions (automated decisioning vs. human investigation console).

---

## What it is

A deterministic, rules-based fraud decision engine driven entirely by a single governance file
rather than hard-coded logic. **114 signals** loaded from one JSON governance file, exposed via
a `POST /decide` endpoint. Every decision is fully explainable — each action traces back to the
exact signals that fired and why.

## Why this exists

Fraud rules that live in code are hard to audit and slow to change. This engine's governance
file is the single source of truth: adding, removing, or re-weighting a signal is a data change,
not a code deployment, and every decision remains traceable to that same file.

## Architecture

FastAPI service with a companion memory service, evaluated through a replay-test harness. See
[ARCHITECTURE.md](./ARCHITECTURE.md) for the full request flow.

## Verification

Validated at **92% batch replay accuracy (46/50 exact)** across five fraud typologies —
CLEAN, CARD_TESTING, ATO, MULE, and VELOCITY — run against a 50-event replay suite. The engine
was iteratively improved from an initial 68% accuracy baseline: seven previously-missing signals
were added, one action-severity ordering bug was fixed (BLOCK now always outranks SUSPEND), and
several signal base-score corrections were applied — see [ARCHITECTURE.md](./ARCHITECTURE.md)
for the full iteration history.

## Use cases

Payment platforms and financial institutions that need a fraud decisioning layer where the
rule logic itself — not just the decision — needs to be auditable, versionable, and
explainable to a compliance or regulatory reviewer.

## License

MIT — see [LICENSE](./LICENSE).
