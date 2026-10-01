from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

# Evidence basis. Nothing downstream of an inferred fact may be presented
# as a confirmed source: observed records only; membership/carrier inference
# is always labelled; dangling references stay missing instead of being
# filled with a guess.
OBSERVED = "observed"
INFERRED = "inferred"
MISSING = "missing"

PACK = "pack"
UNPACK = "unpack"


@dataclass(frozen=True)
class Item:
    """A serialized unit or a reusable package (case/pallet, SSCC-like)."""

    serial: str
    product: str
    package: bool = False
    known: bool = True


@dataclass(frozen=True)
class TraceEvent:
    event_id: str
    at: datetime


@dataclass(frozen=True)
class Scan(TraceEvent):
    """A serial was physically observed by a party (scan at receipt/pick)."""

    serial: str
    party: str
    jurisdiction: str | None = None
    location: str | None = None


@dataclass(frozen=True)
class Aggregation(TraceEvent):
    """pack: child enters parent; unpack: child leaves parent."""

    parent: str
    child: str
    action: str


@dataclass(frozen=True)
class Derivation(TraceEvent):
    """Relabelling/rework: output serials are derived from input serials.

    Repacking that keeps inner serials only needs Aggregation events;
    Derivation models new serials minted from old ones.
    """

    output: str
    inputs: tuple[str, ...]


@dataclass(frozen=True)
class Handoff(TraceEvent):
    """Custody transfer. The manifest lists observed serials; anything only
    reached because it was packed inside a listed package stays inferred."""

    from_party: str
    to_party: str
    manifest: tuple[str, ...]
    jurisdiction: str | None = None
    seal: str | None = None


@dataclass(frozen=True)
class Uncertainty:
    """A reason the trace cannot be stated as fact.

    Codes: missing-node, aggregation-cycle, derivation-cycle,
    aggregation-overwrite, seal-reuse, unverified-origin, custody-gap,
    custody-break, unauthorized-market.
    """

    code: str
    subject: str
    detail: str
    evidence: tuple[str, ...] = ()
