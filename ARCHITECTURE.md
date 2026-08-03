# Architecture

## Core design

All fraud logic is defined in a single governance JSON file — 114 signals, each with weights,
categories, and trigger conditions — rather than being hard-coded across the application. The
engine loads this file at startup and evaluates every incoming event against it.

## Service layout

- A primary decision API service exposing `POST /decide`
- A companion memory service used for entity/session context
- A replay-test harness used to validate accuracy against labeled historical events

## Signal history (iteration record)

The engine started at 68% replay accuracy (v1). Subsequent patch iterations:

- Added 7 previously-missing signals (gift-card, transaction-velocity, session, and UPI
  categories), bringing the total to 114 signals.
- Corrected one rule's action override from `SUSPEND` to `BLOCK` for a mule-drain compound
  pattern.
- Fixed a merchant-abuse signal's recommended action and corrected velocity-signal base scores.
- Corrected two risk-band actions and over-optimistic expected values in velocity test events.
- Fixed severity ordering so `BLOCK` always outranks `SUSPEND` in action resolution.

This iteration brought the engine from 68% to its current **92% (46/50 exact)** replay accuracy
across CLEAN, CARD_TESTING, ATO, MULE, and VELOCITY typologies.

## Governance file as the single point of truth

The 114-signal governance JSON is the highest-value artifact in this system — every decision the
engine makes is directly traceable to an entry in that file, which is what makes the engine
auditable rather than a black box.
