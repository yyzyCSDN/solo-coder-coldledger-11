from __future__ import annotations

from dataclasses import dataclass

from .model import OBSERVED, INFERRED, Uncertainty
from .graph import TraceGraph
from .query import (
    TraceReport,
    investigate,
    forward_flow,
)

_BASIS_LABEL = {
    OBSERVED: "confirmed",
    INFERRED: "possible (inferred from package contents)",
    "missing": "unknown (missing record)",
}

_SEVERITY = {
    "custody-break": "HIGH",
    "derivation-cycle": "HIGH",
    "aggregation-cycle": "HIGH",
    "seal-reuse": "HIGH",
    "custody-gap": "MEDIUM",
    "missing-node": "MEDIUM",
    "unverified-origin": "MEDIUM",
    "aggregation-overwrite": "MEDIUM",
    "unauthorized-market": "HIGH",
}


def _ts(at) -> str:
    return at.isoformat() if at is not None else "open"


def render_report(report: TraceReport) -> str:
    """Human-readable explanation. Inferred links are visibly separated from
    observed facts; nothing inferred is phrased as a confirmed source."""
    lines: list[str] = []
    lines.append(f"Trace investigation: {report.serial}")
    lines.append("=" * 60)

    lines.append("")
    lines.append("Custody timeline")
    lines.append("-" * 60)
    if not report.facts:
        lines.append("  (no records)")
    for f in report.facts:
        if f.kind == "handoff":
            lines.append(
                f"  {_ts(f.at)}  handoff {f.party} -> {f.counterparty}  "
                f"[{_BASIS_LABEL.get(f.basis, f.basis)}]  ({f.event_id})  {f.detail}"
            )
        elif f.kind == "scan":
            lines.append(
                f"  {_ts(f.at)}  scan by {f.party}  [{_BASIS_LABEL[OBSERVED]}]  "
                f"({f.event_id})  {f.detail}"
            )
        else:
            lines.append(f"  {_ts(f.at)}  {f.detail}  ({f.event_id})")

    lines.append("")
    lines.append("Reconstructed custody segments")
    lines.append("-" * 60)
    if not report.segments:
        lines.append("  (none)")
    for s in report.segments:
        lines.append(
            f"  {s.party:<14} {_ts(s.since)} .. {_ts(s.until)}  "
            f"[{_BASIS_LABEL.get(s.basis, s.basis)}]  via {s.event_id}"
        )

    lines.append("")
    lines.append("Possible origins")
    lines.append("-" * 60)
    if not report.origins:
        lines.append("  none identifiable")
    for o in report.origins:
        status = "CONFIRMED origin" if o.confirmed else "POSSIBLE origin (not confirmed)"
        product = f" product={o.product}" if o.product else ""
        lines.append(f"  {o.serial:<12}{product}  {status}  evidence={', '.join(o.event_ids) or '-'}")

    lines.append("")
    lines.append("Uncertainties")
    lines.append("-" * 60)
    if not report.findings:
        lines.append("  none")
    for u in report.findings:
        lines.append(f"  [{_SEVERITY.get(u.code, 'INFO')}] {u.code}: {u.subject}")
        lines.append(f"      {u.detail}")
        if u.evidence:
            lines.append(f"      evidence: {', '.join(str(x) for x in u.evidence)}")

    lines.append("")
    lines.append(
        "Legend: 'confirmed' rests on observed scans/manifests; 'possible' is "
        "inferred and must not be treated as a determined source."
    )
    return "\n".join(lines)


@dataclass(frozen=True)
class DiversionHit:
    serial: str
    severity: str
    code: str
    detail: str


def scan_diversion_risk(g: TraceGraph, licenses: list | None = None) -> list[DiversionHit]:
    """Investigate every known serial and collect findings that indicate a
    possible diversion path. Findings are hypotheses for review, sorted by
    severity; the graph never asserts diversion from inference alone."""
    order = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
    hits: list[DiversionHit] = []
    for serial in sorted(g.items):
        report = investigate(g, serial, licenses)
        for u in report.findings:
            hits.append(DiversionHit(
                serial=serial,
                severity=_SEVERITY.get(u.code, "INFO"),
                code=u.code,
                detail=u.detail,
            ))
    hits.sort(key=lambda h: (order.get(h.severity, 3), h.serial, h.code))
    return hits
