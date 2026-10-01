"""Explainable serialization trace graph.

Links physical scans, aggregation (pack/unpack), repacking/relabelling
derivations, cross-party custody handoffs and market authorization into one
evidence-labelled graph. Inferred membership (e.g. a unit riding inside a
manifested case) is always labelled ``inferred`` and reported as a possible
path, never as a confirmed source. Cycles and missing master records are
emitted as :class:`~coldledger.trace.model.Uncertainty` findings.
"""

from .model import (
    OBSERVED,
    INFERRED,
    MISSING,
    PACK,
    UNPACK,
    Item,
    Scan,
    Aggregation,
    Derivation,
    Handoff,
    Uncertainty,
)
from .graph import (
    TraceEdge,
    TraceGraph,
    Membership,
    build_graph,
    SCAN,
    CONTAINS,
    DERIVED_FROM,
    TRANSFER_OF,
    CARRIED,
    AUTHORIZED_FOR,
)
from .query import (
    Fact,
    CustodySegment,
    SourceCandidate,
    TraceReport,
    custody_timeline,
    possible_sources,
    forward_flow,
    investigate,
)
from .report import render_report, scan_diversion_risk, DiversionHit

__all__ = [
    "OBSERVED",
    "INFERRED",
    "MISSING",
    "PACK",
    "UNPACK",
    "Item",
    "Scan",
    "Aggregation",
    "Derivation",
    "Handoff",
    "Uncertainty",
    "TraceEdge",
    "TraceGraph",
    "Membership",
    "build_graph",
    "SCAN",
    "CONTAINS",
    "DERIVED_FROM",
    "TRANSFER_OF",
    "CARRIED",
    "AUTHORIZED_FOR",
    "Fact",
    "CustodySegment",
    "SourceCandidate",
    "TraceReport",
    "custody_timeline",
    "possible_sources",
    "forward_flow",
    "investigate",
    "render_report",
    "scan_diversion_risk",
    "DiversionHit",
]
