from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime


@dataclass(frozen=True)
class Commission:
    """A serial commissioned (created) by a party, typically the manufacturer."""

    serial: str
    product: str
    party: str
    at: datetime
    ref: str


@dataclass(frozen=True)
class Scan:
    """An observational scan of a serial. kind is scan/receipt/sale/export."""

    serial: str
    party: str
    at: datetime
    ref: str
    kind: str = "scan"
    jurisdiction: str | None = None


@dataclass(frozen=True)
class Pack:
    """Aggregation: contents are sealed into container by party."""

    container: str
    contents: tuple[str, ...]
    party: str
    at: datetime
    ref: str


@dataclass(frozen=True)
class Unpack:
    """Disaggregation: listed contents leave the container at party."""

    container: str
    contents: tuple[str, ...]
    party: str
    at: datetime
    ref: str


@dataclass(frozen=True)
class Repack:
    """Contents move from old_container into new_container at the same party."""

    old_container: str
    new_container: str
    contents: tuple[str, ...]
    party: str
    at: datetime
    ref: str


@dataclass(frozen=True)
class Handoff:
    """Custody transfer of items (serials or containers) between parties."""

    ref: str
    from_party: str
    to_party: str
    at: datetime
    items: tuple[str, ...]
    seal: str | None = None


@dataclass(frozen=True)
class MarketAuth:
    """Market authorization for holder to handle a product in a jurisdiction."""

    holder: str
    jurisdiction: str
    product: str
    valid_from: date
    valid_to: date
    suspended: bool = False
