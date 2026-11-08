"""
poc — ARTP Proof-of-Concept package.

A minimal, runnable demonstration of the claims made in the ARTP paper:
planner (6-action schema, MITRE ATT&CK mapping) -> symbolic/SMT-style verifier
-> human-in-the-loop approval gate -> simulated execution over JSON-RPC
-> metrics per Eqs. 2-9 with CI95 and Welch's t-test.

Everything in this package is SIMULATION-ONLY: no exploit payloads, no live
network attacks. Inputs are sandbox scenario states; outcomes are simulated
deterministically with a seeded PRNG.
"""

__version__ = "1.0.0"
