from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

from .model import (
    PACK,
    UNPACK,
    OBSERVED,
    INFERRED,
    MISSING,
    Item,
    Scan,
    Aggregation,
    Derivation,
    Handoff,
    TraceEvent,
    Uncertainty,
)
SCAN = "scan"                     # party -> item, observed by the party
CONTAINS = "contains"             # package -> child (valid over an interval)
DERIVED_FROM = "derived_from"     # output item -> input item
TRANSFER_OF = "transfer_of"       # party -> party (a handoff event node)
CARRIED = "carried"               # handoff event -> item (observed/inferred)
AUTHORIZED_FOR = "authorized_for" # party -> market node, bounded by dates


@dataclass(frozen=True)
class Membership:
    parent: str
    child: str
    since: datetime
    until: datetime | None = None  # half-open [since, until)


@dataclass(frozen=True)
class TraceEdge:
    source: str
    target: str
    kind: str
    basis: str = OBSERVED
    since: datetime | None = None
    until: datetime | None = None
    event_id: str | None = None
    detail: str = ""

    def active_at(self, at: datetime) -> bool:
        if self.since is not None and at < self.since:
            return False
        if self.until is not None and at >= self.until:
            return False
        return True


@dataclass
class TraceGraph:
    items: dict[str, Item] = field(default_factory=dict)
    parties: set[str] = field(default_factory=set)
    edges: list[TraceEdge] = field(default_factory=list)
    memberships: list[Membership] = field(default_factory=list)
    events: list[TraceEvent] = field(default_factory=list)
    uncertainties: list[Uncertainty] = field(default_factory=list)

    # --- index helpers -------------------------------------------------

    def edges_from(self, node: str) -> list[TraceEdge]:
        return [e for e in self.edges if e.source == node]

    def edges_to(self, node: str) -> list[TraceEdge]:
        return [e for e in self.edges if e.target == node]

    def members_at(self, parent: str, at: datetime) -> set[str]:
        out: set[str] = set()
        for m in self.memberships:
            if m.parent == parent and m.since <= at and (m.until is None or at < m.until):
                out.add(m.child)
        return out

    def ancestors_at(self, serial: str, at: datetime) -> set[str]:
        out: set[str] = set()
        for m in self.memberships:
            if m.child == serial and m.since <= at and (m.until is None or at < m.until):
                if m.parent not in out:
                    out.add(m.parent)
                    out |= self.ancestors_at(m.parent, at)
        return out

    def node_uncertainties(self, node: str) -> list[Uncertainty]:
        return [u for u in self.uncertainties if u.subject == node]


def _event_key(e: TraceEvent):
    # event_id is the deterministic tie breaker so equal timestamps stay stable
    return (e.at, e.event_id)


def build_graph(
    events: list[TraceEvent],
    items: dict[str, Item] | None = None,
    licenses: list | None = None,
    on_date=None,
) -> TraceGraph:
    """Build the explainable trace graph.

    Unknown serials/packages referenced by events are created as
    ``known=False`` placeholder nodes and reported as missing-node
    uncertainties rather than silently dropped or guessed.
    """
    g = TraceGraph()
    items = dict(items or {})
    g.items.update(items)
    g.events = sorted(events, key=_event_key)

    referenced: set[str] = set()
    for e in g.events:
        if isinstance(e, Scan):
            referenced.add(e.serial)
            g.parties.add(e.party)
        elif isinstance(e, Aggregation):
            referenced.add(e.parent)
            referenced.add(e.child)
        elif isinstance(e, Derivation):
            referenced.add(e.output)
            referenced.update(e.inputs)
        elif isinstance(e, Handoff):
            g.parties.add(e.from_party)
            g.parties.add(e.to_party)
            referenced.update(e.manifest)

    for serial in sorted(referenced):
        if serial not in g.items:
            g.items[serial] = Item(serial=serial, product="", package=True, known=False)
            g.uncertainties.append(
                Uncertainty(
                    "missing-node",
                    serial,
                    f"{serial} is referenced by events but has no master record",
                )
            )

    _build_aggregations(g)
    _build_derivations(g)
    _build_handoffs(g)
    _build_scans(g)
    _build_market_authorization(g, licenses or [], on_date)

    return g


def _build_aggregations(g: TraceGraph) -> None:
    open_membership: dict[str, Membership] = {}

    for e in g.events:
        if not isinstance(e, Aggregation):
            continue
        if e.action not in (PACK, UNPACK):
            raise ValueError(f"unknown aggregation action: {e.action}")

        if e.action == PACK:
            if e.child in open_membership:
                prior = open_membership[e.child]
                g.uncertainties.append(
                    Uncertainty(
                        "aggregation-overwrite",
                        e.child,
                        (
                            f"{e.child} packed into {e.parent} at {e.event_id} while already "
                            f"open in {prior.parent} since {prior.since.isoformat()}; "
                            "treating as re-pack, prior link is not a confirmed removal"
                        ),
                        (prior.parent, e.event_id),
                    )
                )
                g.memberships.append(
                    Membership(prior.parent, prior.child, prior.since, until=e.at)
                )
            if _contains_cycle(g, e.parent, e.child, e.at):
                g.uncertainties.append(
                    Uncertainty(
                        "aggregation-cycle",
                        e.child,
                        f"packing {e.child} into {e.parent} would nest a package inside its own contents",
                        (e.event_id,),
                    )
                )
                # The structural record is kept; the cyclic membership is not.
                continue
            m = Membership(e.parent, e.child, e.at)
            open_membership[e.child] = m
            g.memberships.append(m)
            g.edges.append(
                TraceEdge(e.parent, e.child, CONTAINS, OBSERVED, since=e.at, event_id=e.event_id)
            )
        else:  # UNPACK
            prior = open_membership.get(e.child)
            if prior is None or prior.parent != e.parent:
                g.uncertainties.append(
                    Uncertainty(
                        "custody-break",
                        e.child,
                        f"unpack event {e.event_id} removes {e.child} from {e.parent}, "
                        "but no open packing into that parent exists",
                        (e.event_id,),
                    )
                )
                continue
            idx = g.memberships.index(prior)
            g.memberships[idx] = Membership(prior.parent, prior.child, prior.since, until=e.at)
            open_membership.pop(e.child, None)
            edge = next(
                x
                for x in g.edges
                if x.kind == CONTAINS and x.source == e.parent and x.target == e.child and x.until is None
            )
            g.edges[g.edges.index(edge)] = TraceEdge(
                edge.source, edge.target, edge.kind, edge.basis,
                since=edge.since, until=e.at, event_id=edge.event_id,
            )


def _contains_cycle(g: TraceGraph, parent: str, child: str, at: datetime) -> bool:
    """Packing `child` into `parent` is cyclic if `child` already (transitively)
    contains `parent` at that time."""
    stack = [child]
    seen = set()
    while stack:
        cur = stack.pop()
        for m in g.memberships:
            if m.parent == cur and m.since <= at and (m.until is None or at < m.until):
                if m.child == parent:
                    return True
                if m.child not in seen:
                    seen.add(m.child)
                    stack.append(m.child)
    return False


def _build_derivations(g: TraceGraph) -> None:
    for e in g.events:
        if not isinstance(e, Derivation):
            continue
        for s in e.inputs:
            g.edges.append(
                TraceEdge(e.output, s, DERIVED_FROM, OBSERVED, since=e.at, event_id=e.event_id)
            )
    # Cycle detection on the derivation graph (rework loops from bad feeds).
    color: dict[str, int] = defaultdict(int)

    def visit(node: str, stack: tuple[str, ...]) -> None:
        color[node] = 1
        for edge in g.edges_from(node):
            if edge.kind != DERIVED_FROM:
                continue
            if color[edge.target] == 1:
                g.uncertainties.append(
                    Uncertainty(
                        "derivation-cycle",
                        edge.target,
                        "derivation inputs form a cycle; lineage through the cycle is "
                        "reported as possible, not confirmed",
                        tuple(reversed(stack + (edge.target,))),
                    )
                )
            elif color[edge.target] == 0:
                visit(edge.target, stack + (edge.target,))
        color[node] = 2

    for serial in sorted(g.items):
        if color[serial] == 0:
            visit(serial, (serial,))


def _build_handoffs(g: TraceGraph) -> None:
    seen_seals: dict[str, str] = {}
    for e in g.events:
        if not isinstance(e, Handoff):
            continue
        if e.seal:
            if e.seal in seen_seals:
                g.uncertainties.append(
                    Uncertainty(
                        "seal-reuse",
                        e.seal,
                        f"seal {e.seal} reused by {e.event_id}; first used on "
                        f"{seen_seals[e.seal]}",
                        (seen_seals[e.seal], e.event_id),
                    )
                )
            else:
                seen_seals[e.seal] = e.event_id

        node = f"handoff:{e.event_id}"
        g.edges.append(
            TraceEdge(e.from_party, e.to_party, TRANSFER_OF, OBSERVED,
                      since=e.at, event_id=e.event_id, detail=node)
        )
        observed = set(e.manifest)
        # Expand package contents at handoff time. Directly listed units and
        # units listed inside packages are observed (manifested) too.
        manifested: set[str] = set(observed)
        frontier = list(observed)
        while frontier:
            cur = frontier.pop()
            for child in g.members_at(cur, e.at):
                if child not in manifested:
                    manifested.add(child)
                    frontier.append(child)
        for serial in sorted(manifested):
            g.edges.append(
                TraceEdge(node, serial, CARRIED,
                          OBSERVED if serial in observed else INFERRED,
                          since=e.at, event_id=e.event_id,
                          detail="manifested package contents" if serial not in observed else "")
            )


def _build_scans(g: TraceGraph) -> None:
    for e in g.events:
        if isinstance(e, Scan):
            g.edges.append(
                TraceEdge(e.party, e.serial, SCAN, OBSERVED, since=e.at, event_id=e.event_id)
            )


def _build_market_authorization(g: TraceGraph, licenses: list, on_date) -> None:
    if not licenses:
        return
    for lic in licenses:
        g.parties.add(lic.holder)
        market = f"market:{lic.jurisdiction}:{lic.product_class}"
        g.edges.append(
            TraceEdge(
                lic.holder,
                market,
                AUTHORIZED_FOR,
                MISSING if lic.suspended else OBSERVED,
                event_id=f"license:{lic.holder}:{lic.jurisdiction}:{lic.product_class}",
                detail=(
                    f"valid {lic.valid_from.isoformat()}..{lic.valid_to.isoformat()}"
                    + (" SUSPENDED" if lic.suspended else "")
                ),
            )
        )
