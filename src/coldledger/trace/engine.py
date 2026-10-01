from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .builder import TraceGraph, node, split_node
from .model import Scan
from .uncertainty import CYCLE, MULTIPLE_ORIGINS, Uncertainty

CONFIRMED = "confirmed"
UNCERTAIN = "uncertain"

MAX_PATHS = 200
MAX_DEPTH = 100


@dataclass(frozen=True)
class Hop:
    party: str
    serial: str
    kind: str
    at: datetime
    ref: str

    def explain(self) -> str:
        return f"{self.at.isoformat()} {self.kind:<18} {self.party} · {self.serial} [{self.ref}]"


@dataclass
class TracePath:
    hops: list[Hop]                      # chronological, origin -> terminal
    origin_party: str | None
    origin_serial: str | None
    confidence: str
    uncertainty_codes: tuple[str, ...] = ()

    def explain(self) -> str:
        lines = [f"origin={self.origin_party or '?'} · confidence={self.confidence}"]
        if self.uncertainty_codes:
            lines.append("uncertainty=" + ",".join(self.uncertainty_codes))
        lines.extend("  " + h.explain() for h in self.hops)
        return "\n".join(lines)


@dataclass
class TraceResult:
    serial: str
    as_of: datetime | None
    paths: list[TracePath] = field(default_factory=list)
    uncertainties: list[Uncertainty] = field(default_factory=list)
    diversion_nodes: list[str] = field(default_factory=list)

    @property
    def confidence(self) -> str:
        if not self.paths:
            return UNCERTAIN
        if any(p.confidence == UNCERTAIN for p in self.paths):
            return UNCERTAIN
        origins = {(p.origin_party, p.origin_serial) for p in self.paths}
        return CONFIRMED if len(origins) == 1 else UNCERTAIN

    def explain(self) -> str:
        body = [f"trace {self.serial}: {len(self.paths)} path(s), "
                f"confidence={self.confidence}"]
        body.extend("  ! " + u.explain() for u in self.uncertainties)
        for i, p in enumerate(self.paths, 1):
            body.append(f"path {i}:")
            body.extend("  " + h.explain() for h in p.hops)
        return "\n".join(body)


class Tracer:
    """Multi-hop provenance walks over a possession-state graph.

    Walks never raise on bad data: cycles terminate the offending path with a
    ``cycle`` code and phantom nodes terminate it as unconfirmed, so a guessed
    predecessor can never surface as a confirmed origin.
    """

    def __init__(self, graph: TraceGraph):
        self.g = graph
        by_ref: dict[str, list[Uncertainty]] = {}
        for u in graph.uncertainties:
            if u.ref:
                by_ref.setdefault(u.ref, []).append(u)
        self._by_ref = by_ref

    def _ref_codes(self, ref: str) -> tuple[str, ...]:
        return tuple(sorted({u.code for u in self._by_ref.get(ref, [])}))

    # -- backward trace ----------------------------------------------------

    def trace_back(self, serial: str, as_of: datetime | None = None) -> TraceResult:
        g = self.g
        result = TraceResult(serial, as_of)
        start_party = g.holder_at(serial, as_of) or g.latest_holder(serial)
        if start_party is None:
            result.uncertainties.append(Uncertainty(
                "missing_node", f"no record of serial {serial} anywhere", as_of))
            return result
        start = node(start_party, serial)
        # (node, chronological chain, per-path visited, uncertainty codes).
        # The carried serial stays `serial` across container nodes: state for a
        # member riding inside case C is represented by node (party, C), but
        # edges there still carry the member serial.
        stack: list[tuple[str, list, set[str], tuple[str, ...]]] = [
            (start, [], {start}, ())]
        while stack and len(result.paths) < MAX_PATHS:
            cur, chain, visited, codes = stack.pop()
            party = split_node(cur)[0]
            # A commission edge ending here is a certified origin: stop.
            commissioned = next(
                (e for e in g.incoming(cur)
                 if e.serial == serial and e.kind == "commission"
                 and (as_of is None or e.at <= as_of)
                 and (not chain or e.at <= chain[0][1].at)), None)
            if commissioned is not None:
                hop = Hop(party, serial, "commission", commissioned.at,
                          commissioned.ref)
                result.paths.append(TracePath(
                    [hop] + [c[0] for c in chain], party, serial,
                    CONFIRMED if not codes else UNCERTAIN, codes))
                continue
            if cur in g.phantoms:
                result.paths.append(TracePath(
                    [c[0] for c in chain], None, serial, UNCERTAIN,
                    tuple(dict.fromkeys(codes)) or ("missing_node",)))
                continue
            edges = [e for e in g.incoming(cur)
                     if e.source and e.serial == serial
                     and not e.kind.startswith("scan")
                     and (as_of is None or e.at <= as_of)
                     and (not chain or e.at <= chain[0][1].at)]
            if not edges:
                result.paths.append(TracePath(
                    [c[0] for c in chain], party, serial, UNCERTAIN,
                    tuple(dict.fromkeys(codes))))
                continue
            for e in edges:
                hop = Hop(party, serial, e.kind, e.at, e.ref)
                new_codes = tuple(dict.fromkeys(codes + self._ref_codes(e.ref)))
                if e.source in visited or len(chain) >= MAX_DEPTH:
                    cyc = tuple(dict.fromkeys(new_codes + (CYCLE,)))
                    result.paths.append(TracePath(
                        [c[0] for c in chain], None, serial, UNCERTAIN, cyc))
                    continue
                stack.append((e.source, [(hop, e)] + chain,
                              visited | {e.source}, new_codes))
        self._collect_serial_uncertainties(result)
        confirmed_origins = {(p.origin_party) for p in result.paths
                             if p.confidence == CONFIRMED and p.origin_party}
        if len(confirmed_origins) > 1:
            result.uncertainties.append(Uncertainty(
                MULTIPLE_ORIGINS,
                f"{serial} has {len(confirmed_origins)} distinct confirmed-looking "
                f"origins: {sorted(confirmed_origins)}", as_of))
        return result

    # -- forward trace -----------------------------------------------------

    def trace_forward(self, serial: str, as_of: datetime | None = None) -> TraceResult:
        g = self.g
        result = TraceResult(serial, as_of)
        rows = g.history.get(serial, [])
        start_party = rows[0][1] if rows else None
        if start_party is None:
            result.uncertainties.append(Uncertainty(
                "missing_node", f"no record of serial {serial} anywhere", as_of))
            return result
        start = node(start_party, serial)
        stack: list[tuple[str, list, set[str], tuple[str, ...]]] = [
            (start, [], {start}, ())]
        while stack and len(result.paths) < MAX_PATHS:
            cur, chain, visited, codes = stack.pop()
            party = split_node(cur)[0]
            edges = [e for e in g.outgoing(cur)
                     if e.target and e.serial == serial
                     and not e.kind.startswith("scan")
                     and (as_of is None or e.at >= as_of)
                     and (not chain or e.at >= chain[-1][0].at)]
            if not edges:
                result.paths.append(TracePath(
                    [c[0] for c in chain],
                    chain[0][0].party if chain else party,
                    serial,
                    CONFIRMED if not codes else UNCERTAIN,
                    tuple(dict.fromkeys(codes))))
                continue
            for e in edges:
                hop = Hop(party, serial, e.kind, e.at, e.ref)
                new_codes = tuple(dict.fromkeys(codes + self._ref_codes(e.ref)))
                if e.target in visited or len(chain) >= MAX_DEPTH:
                    result.paths.append(TracePath(
                        [c[0] for c in chain] + [hop], None, serial, UNCERTAIN,
                        tuple(dict.fromkeys(new_codes + (CYCLE,)))))
                    continue
                stack.append((e.target, chain + [(hop, e)],
                              visited | {e.target}, new_codes))
        self._collect_serial_uncertainties(result)
        self._mark_diversion(result)
        return result

    # -- shared ------------------------------------------------------------

    def _collect_serial_uncertainties(self, result: TraceResult) -> None:
        seen = set()
        for e in self.g.edges:
            if e.serial != result.serial:
                continue
            for u in self._by_ref.get(e.ref, []):
                if u.code not in seen:
                    result.uncertainties.append(u)
                    seen.add(u.code)
        result.uncertainties.sort(key=lambda u: (u.at or result.as_of or 0, u.code))

    def _mark_diversion(self, result: TraceResult) -> None:
        # Market observations are scan records (not flow edges), so they are
        # matched by serial rather than discovered while walking.
        flagged: set[str] = set()
        for n, scans in self.g.market_nodes.items():
            if split_node(n)[1] != result.serial:
                continue
            for s in scans:
                if s.kind in ("sale", "export") and not self._authorized(s):
                    flagged.add(n)
        result.diversion_nodes = sorted(flagged)

    def _authorized(self, s: Scan) -> bool:
        product = self.g.product_of.get(s.serial)
        if product is None or not s.jurisdiction:
            return False
        for a in self.g.auths:
            if (a.holder == s.party and a.jurisdiction == s.jurisdiction
                    and a.product in {product, "*"}
                    and a.valid_from <= s.at.date() <= a.valid_to
                    and not a.suspended):
                return True
        return False
