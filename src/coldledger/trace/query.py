from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from collections import defaultdict

from ..compliance.license_registry import valid_license
from .model import (
    PACK,
    OBSERVED,
    INFERRED,
    Scan,
    Aggregation,
    Derivation,
    Handoff,
    Uncertainty,
)
from .graph import (
    TraceGraph,
    CONTAINS,
    DERIVED_FROM,
)


@dataclass(frozen=True)
class Fact:
    at: datetime
    kind: str  # scan | pack | unpack | handoff | derive
    party: str | None
    counterparty: str | None
    event_id: str
    basis: str
    detail: str = ""
    jurisdiction: str | None = None


@dataclass(frozen=True)
class CustodySegment:
    party: str
    since: datetime
    until: datetime | None
    basis: str  # observed: direct scan/manifest; inferred: only via package
    event_id: str


@dataclass(frozen=True)
class SourceCandidate:
    serial: str
    product: str
    event_ids: tuple[str, ...]
    confirmed: bool  # False => only a possible source


@dataclass
class TraceReport:
    serial: str
    facts: list[Fact]
    segments: list[CustodySegment]
    origins: list[SourceCandidate]
    findings: list[Uncertainty] = field(default_factory=list)

    @property
    def confirmed_origin(self) -> SourceCandidate | None:
        confirmed = [o for o in self.origins if o.confirmed]
        return confirmed[0] if len(confirmed) == 1 else None


def dedup_findings(findings: list[Uncertainty]) -> list[Uncertainty]:
    seen: set[tuple] = set()
    out: list[Uncertainty] = []
    for u in findings:
        key = (u.code, u.subject, u.detail)
        if key not in seen:
            seen.add(key)
            out.append(u)
    return out


def _index_licenses(licenses: list) -> dict[str, list]:
    out: dict[str, list] = defaultdict(list)
    for lic in licenses:
        out[lic.holder].append(lic)
    return dict(out)


def _carried_serial(g: TraceGraph, e: Handoff) -> tuple[set[str], set[str]]:
    """Return (observed_serials, inferred_serials) covered by a handoff."""
    observed: set[str] = set(e.manifest)
    covered: set[str] = set(observed)
    frontier = list(observed)
    while frontier:
        cur = frontier.pop()
        for child in g.members_at(cur, e.at):
            if child not in covered:
                covered.add(child)
                frontier.append(child)
    return observed, covered - observed


def _check_authorization(
    licenses_by_holder: dict[str, list],
    party: str,
    product: str,
    jurisdiction: str | None,
    on: date,
    event_id: str,
) -> Uncertainty | None:
    if not jurisdiction or not product:
        return None
    if valid_license(party, jurisdiction, product, on, licenses_by_holder.get(party, [])) is None:
        return Uncertainty(
            "unauthorized-market",
            party,
            f"{party} has no valid market authorization for {product} in {jurisdiction} "
            f"on {on.isoformat()} (first seen at {event_id})",
            (event_id,),
        )
    return None


def _same_unauthorized(findings: list[Uncertainty], u: Uncertainty) -> bool:
    return any(
        x.code == "unauthorized-market"
        and x.subject == u.subject
        and x.detail.split(" (first seen")[0] == u.detail.split(" (first seen")[0]
        for x in findings
    )


def custody_timeline(
    g: TraceGraph, serial: str, licenses: list | None = None
) -> tuple[list[Fact], list[CustodySegment], list[Uncertainty]]:
    """Reconstruct what is known about one serial, earliest first.

    Holder changes backed only by package-inference are kept separate from
    observed holder changes; gaps and cross-party discontinuities are
    reported, never papered over.
    """
    licenses_by_holder = _index_licenses(licenses or [])
    product = g.items.get(serial).product if serial in g.items else ""

    facts: list[Fact] = []
    for e in g.events:
        if isinstance(e, Scan) and e.serial == serial:
            detail = f"scan at {e.location}" if e.location else "scan"
            facts.append(Fact(e.at, "scan", e.party, None, e.event_id, OBSERVED,
                              detail, e.jurisdiction))
        elif isinstance(e, Aggregation) and e.child == serial:
            verb = "into" if e.action == PACK else "from"
            facts.append(Fact(
                e.at, e.action, None, e.parent, e.event_id, OBSERVED,
                f"{e.action} {serial} {verb} {e.parent}",
            ))
        elif isinstance(e, Derivation) and (serial == e.output or serial in e.inputs):
            role = "output" if serial == e.output else "input"
            facts.append(Fact(e.at, "derive", None, None, e.event_id, OBSERVED,
                              f"{serial} is a derivation {role}"))
        elif isinstance(e, Handoff):
            observed, inferred = _carried_serial(g, e)
            if serial in observed or serial in inferred:
                facts.append(Fact(
                    e.at, "handoff", e.from_party, e.to_party, e.event_id,
                    OBSERVED if serial in observed else INFERRED,
                    "direct manifest" if serial in observed else "inferred from package contents",
                    e.jurisdiction,
                ))

    facts.sort(key=lambda f: (f.at, f.event_id))

    segments: list[CustodySegment] = []
    findings: list[Uncertainty] = []
    holder: str | None = None
    segment_since: datetime | None = None
    segment_basis: str | None = None
    segment_event: str | None = None

    def open_next(new_holder: str, at: datetime, basis: str, event_id: str) -> None:
        nonlocal holder, segment_since, segment_basis, segment_event
        if holder is not None and segment_since is not None:
            segments.append(CustodySegment(holder, segment_since, at, segment_basis, segment_event))
        holder, segment_since, segment_basis, segment_event = new_holder, at, basis, event_id

    for f in facts:
        on_date = f.at.date()
        if f.kind == "scan":
            if holder is None or f.party != holder:
                if holder is not None:
                    findings.append(Uncertainty(
                        "custody-gap",
                        serial,
                        f"{serial} scanned by {f.party} at {f.event_id} while last custody was "
                        f"{holder}; no handoff connects them",
                        (f.event_id,),
                    ))
                open_next(f.party, f.at, OBSERVED, f.event_id)
            elif segment_basis == INFERRED:
                # A confirming scan upgrades an inferred segment to observed.
                segment_basis = OBSERVED
            if f.jurisdiction:
                u = _check_authorization(
                    licenses_by_holder, f.party, product, f.jurisdiction, on_date, f.event_id)
                if u and not _same_unauthorized(findings, u):
                    findings.append(u)

        elif f.kind == "handoff":
            new_holder = f.counterparty
            if holder is None:
                # First evidence is an inferred handoff: we only know the
                # receiver, and the segment is labelled possible rather than
                # inventing the source party as a confirmed holder.
                open_next(new_holder, f.at, f.basis, f.event_id)
            elif f.party == holder:
                open_next(new_holder, f.at, f.basis, f.event_id)
            else:
                # Carrier is not the last known holder. An observed handoff is
                # a hard discontinuity; an inferred one is a possible diversion.
                findings.append(Uncertainty(
                    "custody-break" if f.basis == OBSERVED else "custody-gap",
                    serial,
                    f"handoff {f.event_id} carries {serial} from {f.party}, but the last "
                    f"known holder was {holder}"
                    + ("" if f.basis == OBSERVED else
                       "; carrier inferred from package, diversion path possible"),
                    (f.event_id,),
                ))
                open_next(new_holder, f.at, f.basis, f.event_id)
            if f.jurisdiction:
                u = _check_authorization(
                    licenses_by_holder, new_holder, product, f.jurisdiction, on_date, f.event_id)
                if u and not _same_unauthorized(findings, u):
                    findings.append(u)

        # pack/unpack/derive facts are evidence in the timeline but do not
        # themselves move custodial holder.

    if holder is not None and segment_since is not None:
        segments.append(CustodySegment(holder, segment_since, None, segment_basis, segment_event))

    findings.extend(u for u in g.uncertainties if u.subject == serial)
    return facts, _merge_segments(segments), dedup_findings(findings)


def _merge_segments(segments: list[CustodySegment]) -> list[CustodySegment]:
    out: list[CustodySegment] = []
    for s in segments:
        if out and out[-1].party == s.party and out[-1].until == s.since:
            basis = OBSERVED if OBSERVED in (out[-1].basis, s.basis) else INFERRED
            out[-1] = CustodySegment(s.party, out[-1].since, s.until, basis, s.event_id)
        else:
            out.append(s)
    return out


# ---------------------------------------------------------------------------
# Backward lineage: possible sources across unpack / repack / derivation
# ---------------------------------------------------------------------------

def possible_sources(
    g: TraceGraph, serial: str
) -> tuple[list[SourceCandidate], list[Uncertainty]]:
    """Find every originating serial for ``serial``.

    Origin traversal follows two different link semantics:

    * ``derived_from`` edges change identity (rework/relabel mints a new
      serial) and are followed to their inputs;
    * ``contains`` (pack/unpack) is only carriage. It does not change where
      a unit came from, but a *missing package* on a unit's history still
      taints the origin: the carriage path itself is unverified.

    A root is confirmed only when every derivation path is observed and
    touches no missing node or cycle.
    """
    findings: list[Uncertainty] = []
    root_events: dict[str, set[str]] = defaultdict(set)
    root_confirmed: dict[str, bool] = defaultdict(lambda: True)
    cycle_reported: set[tuple] = set()

    def walk(node: str, path: tuple[str, ...], events: tuple[str, ...], clean: bool) -> None:
        # derived_from edges point output -> input, so predecessors in the
        # origin sense are the node's outgoing derivation edges.
        derivations = [e for e in g.edges_from(node) if e.kind == DERIVED_FROM]
        # Missing packages the node was ever carried in taint the carriage
        # history but do not redirect the origin.
        for edge in g.edges_to(node):
            if edge.kind != CONTAINS:
                continue
            pkg = edge.source
            pkg_item = g.items.get(pkg)
            if pkg_item is not None and not pkg_item.known:
                clean = False
                findings.append(Uncertainty(
                    "missing-node", pkg,
                    f"{node} was packed in {pkg}, which has no master record; the carriage "
                    "path to its origin is unverified",
                    (edge.event_id,) if edge.event_id else (),
                ))
        if not derivations:
            root_events[node].update(events)
            root_confirmed[node] &= clean
            return
        for e in derivations:
            pred = e.target  # edge is output -> input
            ev = events + ((e.event_id,) if e.event_id else ())
            if pred == node:
                findings.append(Uncertainty(
                    "derivation-cycle",
                    pred,
                    f"{serial} lists itself as a derivation input; lineage is a possible, "
                    "not confirmed, source",
                    tuple(reversed(path + (pred,))),
                ))
                root_events[pred].update(ev)
                root_confirmed[pred] = False
                continue
            if pred in path:
                key = (node, pred)
                if key not in cycle_reported:
                    cycle_reported.add(key)
                    findings.append(Uncertainty(
                        "derivation-cycle",
                        pred,
                        f"lineage of {serial} loops through {pred}; that branch is a possible, "
                        "not confirmed, source",
                        tuple(reversed(path + (pred,))),
                    ))
                root_events[pred].update(ev)
                root_confirmed[pred] = False
                continue
            item = g.items.get(pred)
            branch_clean = clean and item is not None and item.known
            if item is not None and not item.known:
                findings.append(Uncertainty(
                    "missing-node", pred,
                    f"derivation input {pred} of {serial} has no master record; origin via it "
                    "is unverified",
                    (e.event_id,) if e.event_id else (),
                ))
            walk(pred, path + (pred,), ev, branch_clean)

    item = g.items.get(serial)
    walk(serial, (), (), item is not None and item.known)

    candidates = [
        SourceCandidate(
            serial=root,
            product=(g.items[root].product if root in g.items else ""),
            event_ids=tuple(sorted(root_events[root])),
            confirmed=root_confirmed[root]
            and not any(u.subject == root for u in g.uncertainties),
        )
        for root in sorted(root_events)
    ]
    findings = dedup_findings(findings)
    return candidates, findings


# ---------------------------------------------------------------------------
# Forward flow: who could have received a serial
# ---------------------------------------------------------------------------

def forward_flow(g: TraceGraph, serial: str) -> tuple[list[tuple[str, str, str]], list[Uncertainty]]:
    """All (from_party, to_party, basis) handoffs covering the serial, in time."""
    rows: list[tuple[str, str, str]] = []
    for e in g.events:
        if not isinstance(e, Handoff):
            continue
        observed, inferred = _carried_serial(g, e)
        if serial in observed:
            rows.append((e.from_party, e.to_party, OBSERVED))
        elif serial in inferred:
            rows.append((e.from_party, e.to_party, INFERRED))
    findings = [u for u in g.uncertainties if u.subject == serial]
    return rows, dedup_findings(findings)


# ---------------------------------------------------------------------------
# Full investigation
# ---------------------------------------------------------------------------

def investigate(g: TraceGraph, serial: str, licenses: list | None = None) -> TraceReport:
    facts, segments, findings = custody_timeline(g, serial, licenses)
    origins, origin_findings = possible_sources(g, serial)
    if serial in g.items and not g.items[serial].known:
        origin_findings.append(Uncertainty(
            "missing-node", serial,
            f"{serial} has no master record; any origin reported for it is unverified",
        ))
    if not origins:
        origin_findings.append(Uncertainty(
            "unverified-origin", serial,
            f"no aggregation or derivation event identifies an origin for {serial}",
        ))
    return TraceReport(
        serial=serial,
        facts=facts,
        segments=segments,
        origins=origins,
        findings=dedup_findings(findings + origin_findings),
    )
