from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime

from .model import Commission, Handoff, MarketAuth, Pack, Repack, Scan, Unpack
from .uncertainty import (
    CONFLICT,
    CUSTODY_GAP,
    MISSING_CONTENTS,
    MISSING_NODE,
    UNAUTHORIZED_MARKET,
    UNKNOWN_PRODUCT,
    UNVERIFIED_SEAL,
    Uncertainty,
)


def node(party: str, serial: str) -> str:
    return f"{party}|{serial}"


def split_node(n: str) -> tuple[str, str]:
    p, _, s = n.partition("|")
    return p, s


@dataclass(frozen=True)
class FlowEdge:
    source: str
    target: str
    serial: str          # the unit whose possession this edge moves
    kind: str            # commission|pack|unpack|repack|handoff|handoff_contained
    at: datetime
    ref: str
    flagged: bool = False  # an uncertainty already attaches to this transition


@dataclass
class TraceGraph:
    edges: list[FlowEdge] = field(default_factory=list)
    nodes: set[str] = field(default_factory=set)
    product_of: dict[str, str] = field(default_factory=dict)
    phantoms: set[str] = field(default_factory=set)
    commissioned: set[str] = field(default_factory=set)
    uncertainties: list[Uncertainty] = field(default_factory=list)
    # serial -> list of (at, party) possession changes, chronological
    history: dict[str, list[tuple[datetime, str]]] = field(default_factory=dict)
    auths: list[MarketAuth] = field(default_factory=list)
    # nodes where an outward market observation (sale/export) happened
    market_nodes: dict[str, list[Scan]] = field(default_factory=dict)

    def outgoing(self, n: str) -> list[FlowEdge]:
        return [e for e in self.edges if e.source == n]

    def incoming(self, n: str) -> list[FlowEdge]:
        return [e for e in self.edges if e.target == n]

    def holder_at(self, serial: str, at: datetime | None) -> str | None:
        rows = self.history.get(serial, [])
        if at is None:
            return rows[-1][1] if rows else None
        holder = None
        for t, p in rows:
            if t <= at:
                holder = p
            else:
                break
        return holder

    def latest_holder(self, serial: str) -> str | None:
        rows = self.history.get(serial, [])
        return rows[-1][1] if rows else None


class GraphBuilder:
    """Replays serialization, aggregation and custody records chronologically.

    Contradictory or missing records never raise: they become Uncertainty
    entries while the maximal supported graph is still built, so downstream
    tracing reports hypotheses rather than failing closed or guessing.
    """

    def __init__(self) -> None:
        self.g = TraceGraph()
        self._holder: dict[str, str] = {}
        self._contents: dict[str, set[str]] = {}
        self._is_container: set[str] = set()
        self._declared: set[str] = set()
        # member serial -> container it is currently aggregated inside (if any)
        self._inside: dict[str, str] = {}
        self._seals: set[str] = set()

    # -- helpers -----------------------------------------------------------

    def _touch(self, party: str, serial: str, phantom: bool = False) -> str:
        n = node(party, serial)
        self.g.nodes.add(n)
        if phantom:
            self.g.phantoms.add(n)
        return n

    def _set_holder(self, serial: str, party: str, at: datetime) -> None:
        if self._holder.get(serial) != party:
            self._holder[serial] = party
            self.g.history.setdefault(serial, []).append((at, party))

    def _flag(self, code: str, detail: str, at: datetime | None, ref: str | None,
              serial: str | None = None) -> Uncertainty:
        party = self._holder.get(serial) if serial else None
        n = node(party, serial) if party and serial else None
        u = Uncertainty(code, detail, at, ref, n)
        self.g.uncertainties.append(u)
        return u

    def _auth_ok(self, party: str, product: str, on: date, jurisdiction: str) -> bool:
        for a in self.g.auths:
            if (a.holder == party and a.jurisdiction == jurisdiction
                    and a.product in {product, "*"}
                    and a.valid_from <= on <= a.valid_to and not a.suspended):
                return True
        return False

    # -- record ingestion --------------------------------------------------

    def commission(self, e: Commission) -> None:
        n = self._touch(e.party, e.serial)
        if e.serial in self.g.commissioned:
            u = self._flag(CONFLICT, f"serial {e.serial} commissioned more than once",
                           e.at, e.ref, e.serial)
        elif e.serial in self._holder:
            u = self._flag(CONFLICT,
                           f"commission of serial already in circulation: {e.serial}",
                           e.at, e.ref, e.serial)
        else:
            u = None
        self.g.commissioned.add(e.serial)
        self.g.product_of[e.serial] = e.product
        self._set_holder(e.serial, e.party, e.at)
        self.g.edges.append(FlowEdge("", n, e.serial, "commission", e.at, e.ref,
                                     u is not None))

    def scan(self, e: Scan) -> None:
        n = self._touch(e.party, e.serial, phantom=e.serial not in self._holder
                        and e.serial not in self.g.commissioned)
        u = None
        if e.serial not in self._holder and e.serial not in self.g.commissioned:
            u = self._flag(MISSING_NODE,
                           f"scan of {e.serial} with no prior custody or commission record",
                           e.at, e.ref, e.serial)
            self._set_holder(e.serial, e.party, e.at)
        elif self._holder.get(e.serial) not in (None, e.party):
            u = self._flag(CUSTODY_GAP,
                           f"{e.party} scanned {e.serial} held by "
                           f"{self._holder[e.serial]}; no handoff record",
                           e.at, e.ref, e.serial)
            self._set_holder(e.serial, e.party, e.at)
        self.g.edges.append(FlowEdge(n, n, e.serial, f"scan:{e.kind}", e.at, e.ref,
                                     u is not None))
        # If the member is still recorded as aggregated in a container held by
        # this party, observing it loose proves de-aggregation happened even
        # without an unpack record. Link the container state to this node so
        # provenance stays walkable; the observation edge carries no record
        # ref of its own beyond the scan.
        enc = self._inside.get(e.serial)
        if enc and self._holder.get(enc) == e.party:
            cn = self._touch(e.party, enc)
            self.g.edges.append(FlowEdge(cn, n, e.serial, "disaggregate_observed",
                                         e.at, e.ref, u is not None))
            self._inside.pop(e.serial, None)
        if e.kind in ("sale", "export"):
            self.g.market_nodes.setdefault(n, []).append(e)
            product = self.g.product_of.get(e.serial)
            if product is None:
                self._flag(UNKNOWN_PRODUCT,
                           f"cannot check market authorization for {e.serial}: product unknown",
                           e.at, e.ref, e.serial)
            elif e.jurisdiction and not self._auth_ok(e.party, product, e.at.date(),
                                                      e.jurisdiction):
                self._flag(UNAUTHORIZED_MARKET,
                           f"{e.party} {e.kind} {product} ({e.serial}) in "
                           f"{e.jurisdiction} without valid authorization",
                           e.at, e.ref, e.serial)

    def pack(self, e: Pack) -> None:
        cn = self._touch(e.party, e.container)
        if e.container in self._contents and self._contents[e.container]:
            self._flag(CONFLICT,
                       f"container {e.container} re-sealed while still holding contents",
                       e.at, e.ref, e.container)
        if self._holder.get(e.container) not in (None, e.party):
            self._flag(CUSTODY_GAP,
                       f"{e.party} packed container {e.container} held by "
                       f"{self._holder[e.container]}", e.at, e.ref, e.container)
        self._is_container.add(e.container)
        self._declared.add(e.container)
        self._contents[e.container] = set(e.contents)
        for child in e.contents:
            phantom = child not in self._holder and child not in self.g.commissioned
            chn = self._touch(e.party, child, phantom=phantom)
            u = None
            if phantom:
                u = self._flag(MISSING_NODE,
                               f"pack references {child}, which has no prior record",
                               e.at, e.ref, child)
                self._set_holder(child, e.party, e.at)
            elif self._holder.get(child) not in (None, e.party):
                u = self._flag(CUSTODY_GAP,
                               f"{e.party} packed {child} held by "
                               f"{self._holder[child]}", e.at, e.ref, child)
            self._contents[e.container].add(child)
            self._inside[child] = e.container
            self.g.edges.append(FlowEdge(chn, cn, child, "pack", e.at, e.ref,
                                         u is not None))
        self._set_holder(e.container, e.party, e.at)

    def unpack(self, e: Unpack) -> None:
        cn = self._touch(e.party, e.container,
                         phantom=e.container not in self._is_container
                         and e.container not in self._holder)
        declared = self._contents.get(e.container)
        flag = None
        if declared is None and e.container not in self._is_container:
            flag = self._flag(MISSING_NODE,
                              f"unpack of unknown container {e.container}",
                              e.at, e.ref, e.container)
            self._set_holder(e.container, e.party, e.at)
        elif self._holder.get(e.container) not in (None, e.party):
            flag = self._flag(CUSTODY_GAP,
                              f"{e.party} unpacked container {e.container} held by "
                              f"{self._holder[e.container]}", e.at, e.ref, e.container)
        if declared is None and not flag:
            self._flag(MISSING_CONTENTS,
                       f"container {e.container} opened without any declared contents",
                       e.at, e.ref, e.container)
        listed = set(e.contents)
        if declared is not None and not listed <= declared:
            self._flag(CONFLICT,
                       f"unpack lists {sorted(listed - declared)} not recorded in "
                       f"{e.container}", e.at, e.ref, e.container)
        for child in e.contents:
            chn = self._touch(e.party, child)
            self.g.edges.append(FlowEdge(cn, chn, child, "unpack", e.at, e.ref,
                                         flag is not None))
            if self._inside.get(child) == e.container:
                self._inside.pop(child, None)
        self._contents[e.container] = set()
        self._set_holder(e.container, e.party, e.at)

    def repack(self, e: Repack) -> None:
        old = self._touch(e.party, e.old_container)
        new = self._touch(e.party, e.new_container)
        flag = None
        if e.old_container not in self._is_container:
            flag = self._flag(MISSING_NODE,
                              f"repack from unknown container {e.old_container}",
                              e.at, e.ref, e.old_container)
        if self._contents.get(e.new_container):
            self._flag(CONFLICT,
                       f"repack target {e.new_container} already holds contents",
                       e.at, e.ref, e.new_container)
        declared = self._contents.get(e.old_container)
        if e.contents:
            members = tuple(e.contents)
        elif declared is not None and declared:
            members = tuple(sorted(declared))
        else:
            self._flag(MISSING_CONTENTS,
                       f"repack {e.ref} lists no contents and {e.old_container} "
                       f"has none currently aggregated", e.at, e.ref,
                       e.old_container)
            members = ()
        for child in members:
            chn = self._touch(e.party, child,
                              phantom=child not in self._holder
                              and child not in self.g.commissioned)
            if self._inside.get(child) == e.old_container:
                # still sealed in the old container: moves container-to-container
                self.g.edges.append(FlowEdge(old, new, child, "repack", e.at,
                                             e.ref, flag is not None))
            else:
                # loose member (already unpacked) is re-aggregated into new
                self.g.edges.append(FlowEdge(chn, new, child, "repack", e.at,
                                             e.ref, flag is not None))
            self._inside[child] = e.new_container
        self._is_container.add(e.new_container)
        self._declared.add(e.new_container)
        self._contents[e.new_container] = set(members)
        self._contents[e.old_container] = set()
        self._set_holder(e.new_container, e.party, e.at)

    def handoff(self, e: Handoff) -> None:
        flag = None
        if e.from_party == e.to_party:
            self._flag(CONFLICT, f"handoff {e.ref} from and to {e.from_party}",
                       e.at, e.ref)
        if not e.seal:
            self._flag(UNVERIFIED_SEAL,
                       f"handoff {e.ref} carries no seal", e.at, e.ref)
        elif e.seal in self._seals:
            self._flag(CONFLICT, f"seal {e.seal} reused on handoff {e.ref}",
                       e.at, e.ref)
        else:
            self._seals.add(e.seal)
        for item in e.items:
            is_known_container = item in self._is_container
            src = self._touch(e.from_party, item,
                              phantom=item not in self._holder
                              and item not in self.g.commissioned
                              and not is_known_container)
            dst = self._touch(e.to_party, item)
            if (item not in self._holder and item not in self.g.commissioned
                    and not is_known_container):
                flag = self._flag(MISSING_NODE,
                                  f"handoff {e.ref} moves unrecorded item {item}",
                                  e.at, e.ref, item)
            elif self._holder.get(item) not in (None, e.from_party):
                flag = self._flag(CUSTODY_GAP,
                                  f"handoff {e.ref}: {e.from_party} does not hold "
                                  f"{item} (held by {self._holder[item]})",
                                  e.at, e.ref, item)
            kind = "handoff"
            moved = [item]
            declared = self._contents.get(item)
            if is_known_container and item not in self._declared:
                self._flag(MISSING_CONTENTS,
                           f"container {item} crosses custody without declared contents",
                           e.at, e.ref, item)
            # A sealed container moves as a unit: members remain aggregated
            # inside it, so their state rides the container node to the
            # receiving party's container state. A later unpack (or an
            # observed member scan at the recipient) disaggregates them.
            for member in sorted(declared or ()):
                self._touch(e.from_party, member)
                self._touch(e.to_party, member)
                self.g.edges.append(FlowEdge(src, dst, member,
                                             "handoff_contained",
                                             e.at, e.ref, flag is not None))
                self._inside[member] = item
                moved.append(member)
            self.g.edges.append(FlowEdge(src, dst, item, kind, e.at, e.ref,
                                         flag is not None))
            for m in moved:
                self._set_holder(m, e.to_party, e.at)

    # -- build -------------------------------------------------------------

    def build(self, records: list, auths: list[MarketAuth] | None = None) -> TraceGraph:
        self.g.auths = list(auths or [])
        ordered = sorted(enumerate(records), key=lambda x: (x[1].at, x[0]))
        for _, e in ordered:
            if isinstance(e, Commission):
                self.commission(e)
            elif isinstance(e, Scan):
                self.scan(e)
            elif isinstance(e, Pack):
                self.pack(e)
            elif isinstance(e, Unpack):
                self.unpack(e)
            elif isinstance(e, Repack):
                self.repack(e)
            elif isinstance(e, Handoff):
                self.handoff(e)
            else:
                raise TypeError(f"unsupported trace record: {type(e)!r}")
        return self.g
