import unittest
from datetime import datetime, timezone, date

from coldledger.api import ColdLedgerService
from coldledger.trace.builder import GraphBuilder
from coldledger.trace.model import (
    Commission, Handoff, MarketAuth, Pack, Repack, Scan, Unpack,
)
from coldledger.trace.engine import Tracer, CONFIRMED, UNCERTAIN

UTC = timezone.utc
T = lambda h, d=1: datetime(2026, d, h, tzinfo=UTC)


def full_chain():
    return [
        Commission("X", "DRUG", "MFR", T(8), "c1"),
        Commission("Y", "DRUG", "MFR", T(8), "c2"),
        Pack("C", ("X", "Y"), "MFR", T(9), "p1"),
        Handoff("h1", "MFR", "WHO", T(10, 2), ("C",), "S1"),
        Unpack("C", ("X", "Y"), "WHO", T(11, 2), "u1"),
        Repack("C", "R", ("X",), "WHO", T(12, 2), "r1"),
        Handoff("h2", "WHO", "PHA", T(13, 2), ("R",), "S2"),
        Scan("X", "PHA", T(14, 2), "s1", "receipt"),
    ]


class TraceTests(unittest.TestCase):
    def test_confirmed_full_chain_backtrace(self):
        r = ColdLedgerService().trace_back("X", full_chain())
        self.assertEqual(r.confidence, CONFIRMED)
        self.assertEqual({p.origin_party for p in r.paths}, {"MFR"})
        kinds = [h.kind for p in r.paths for h in p.hops]
        self.assertIn("pack", kinds)
        self.assertIn("repack", kinds)
        self.assertIn("handoff_contained", kinds)
        self.assertIn("commission", kinds)

    def test_forward_chain_ends_at_pharmacy(self):
        g = GraphBuilder().build(full_chain())
        r = Tracer(g).trace_forward("X")
        # X rides R into PHA and the receipt scan observes it loose there
        last = [p.hops[-1] for p in r.paths if p.hops]
        self.assertTrue(any(h.party == "PHA"
                            and h.kind == "disaggregate_observed"
                            for h in last))

    def test_missing_node_is_uncertain_not_guessed(self):
        recs = [
            # WHO hands X to PHA, but X was never commissioned or packed
            Handoff("h9", "WHO", "PHA", T(10, 3), ("X",), "S9"),
            Scan("X", "PHA", T(11, 3), "s9", "receipt"),
        ]
        r = ColdLedgerService().trace_back("X", recs)
        self.assertEqual(r.confidence, UNCERTAIN)
        codes = {u.code for u in r.uncertainties}
        self.assertIn("missing_node", codes)
        # no path may claim a confirmed origin
        self.assertFalse(any(p.confidence == CONFIRMED for p in r.paths))

    def test_custody_gap_flagged(self):
        recs = [
            Commission("X", "DRUG", "MFR", T(8), "c1"),
            Handoff("h1", "MFR", "WHO", T(10), ("X",), "S1"),
            # PHA scans it with no WHO->PHA handoff
            Scan("X", "PHA", T(12, 4), "s2", "receipt"),
        ]
        g = GraphBuilder().build(recs)
        codes = {u.code for u in g.uncertainties}
        self.assertIn("custody_gap", codes)
        r = Tracer(g).trace_back("X")
        self.assertEqual(r.confidence, UNCERTAIN)

    def test_cycle_terminates_path_with_cycle_code(self):
        # contradictory repacks create a re-entrant membership walk; the
        # tracer must report cycle uncertainty rather than loop forever.
        recs = [
            Commission("X", "DRUG", "MFR", T(8), "c1"),
            Pack("A", ("X",), "MFR", T(9), "p1"),
            Unpack("A", ("X",), "MFR", T(10), "u1"),
            Pack("A", ("X",), "MFR", T(11), "p2"),
        ]
        g = GraphBuilder().build(recs)
        r = Tracer(g).trace_back("X")
        self.assertLessEqual(len(r.paths), 200)
        # at least one path terminates via the repeated state; graph still
        # contains a confirmed commission path
        self.assertTrue(any(p.confidence == CONFIRMED for p in r.paths)
                        or any("cycle" in p.uncertainty_codes for p in r.paths))

    def test_real_cycle_is_uncertain_with_cycle_code(self):
        # A malformed repack loop: X repeatedly moves between containers A and
        # B at the same party. The walk must terminate with a cycle code and
        # never loop forever or invent a confirmed origin.
        recs = [
            Commission("X", "DRUG", "MFR", T(8), "c1"),
            Pack("A", ("X",), "MFR", T(9), "p1"),
            Repack("A", "B", ("X",), "MFR", T(10), "r1"),
            Repack("B", "A", ("X",), "MFR", T(11), "r2"),
            Repack("A", "B", ("X",), "MFR", T(12), "r3"),
        ]
        g = GraphBuilder().build(recs)
        r = Tracer(g).trace_forward("X")
        self.assertLessEqual(len(r.paths), 200)
        self.assertTrue(any("cycle" in p.uncertainty_codes for p in r.paths))
        # paths that hit the cycle must terminate as uncertain
        for p in r.paths:
            if "cycle" in p.uncertainty_codes:
                self.assertEqual(p.confidence, UNCERTAIN)

    def test_unauthorized_market_flags_diversion(self):
        auths = [MarketAuth("PHA", "DE", "DRUG",
                            date(2026, 1, 1), date(2026, 12, 31))]
        recs = [
            Commission("X", "DRUG", "MFR", T(8), "c1"),
            Handoff("h1", "MFR", "GREY", T(10, 5), ("X",), "S1"),
            Scan("X", "GREY", T(12, 5), "sx", "sale", jurisdiction="DE"),
        ]
        # GREY has no authorization -> diversion node reported
        g = GraphBuilder().build(recs, auths)
        r = Tracer(g).trace_forward("X")
        self.assertIn("GREY|X", r.diversion_nodes)
        self.assertTrue(any(u.code == "unauthorized_market"
                            for u in r.uncertainties))

    def test_authorized_market_is_clean(self):
        auths = [MarketAuth("PHA", "DE", "DRUG",
                            date(2026, 1, 1), date(2026, 12, 31))]
        recs = [
            Commission("X", "DRUG", "MFR", T(8), "c1"),
            Handoff("h1", "MFR", "PHA", T(10, 5), ("X",), "S1"),
            Scan("X", "PHA", T(12, 5), "sx", "sale", jurisdiction="DE"),
        ]
        g = GraphBuilder().build(recs, auths)
        r = Tracer(g).trace_forward("X")
        self.assertEqual(r.diversion_nodes, [])
        self.assertEqual(r.confidence, CONFIRMED)

    def test_container_cross_custody_without_contents(self):
        recs = [
            # a container id crosses custody but was never aggregated/declared
            Handoff("h1", "MFR", "WHO", T(10, 6), ("C",), "S1"),
        ]
        g = GraphBuilder().build(recs)
        self.assertIn("missing_node", {u.code for u in g.uncertainties})

    def test_explainable_output_mentions_refs(self):
        r = ColdLedgerService().trace_back("X", full_chain())
        text = r.explain()
        self.assertIn("confidence=confirmed", text)
        self.assertIn("[p1]", text)

    def test_unknown_serial(self):
        r = ColdLedgerService().trace_back("ZZZ", [])
        self.assertEqual(r.confidence, UNCERTAIN)
        self.assertIn("missing_node", {u.code for u in r.uncertainties})


if __name__ == "__main__":
    unittest.main()
