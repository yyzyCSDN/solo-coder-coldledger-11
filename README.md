# ColdLedger Pharmaceutical Cold-Chain Operations Lab

Dependency-free Python reference implementation for temperature-sensitive pharmaceutical distribution. It models inventory expiry, chain-of-custody, telemetry correction, packaging qualification, dry-ice depletion, freezer allocation, customs holds, serialization, recalls, release decisions, vehicle compartment compatibility, returns, SLA calendars and cross-dock state.

## Serialization trace graph (`coldledger.trace`)

Links scans, pack/unpack aggregation, repack/relabel derivations, cross-party
custody handoffs and market authorization into one explainable graph.

- Every edge carries an evidence basis: `observed` (direct scan/manifest) or
  `inferred` (e.g. a unit riding inside a manifested package). Inferred links
  are always reported as **possible** paths, never as confirmed sources.
- `investigate(graph, serial)` reconstructs the custody timeline, lists
  possible/confirmed origins (following `derived_from` across repacks), and
  attaches uncertainty findings.
- Cycles (package nested in itself, derivation loops), missing master records,
  custody gaps/breaks, seal reuse and missing market authorization are emitted
  as structured `Uncertainty` findings rather than guessed away.
- `render_report` produces a human-readable explanation; `scan_diversion_risk`
  ranks every serial by findings that indicate a possible diversion path.

Runtime third-party dependencies: none.
