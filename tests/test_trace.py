import unittest
from datetime import datetime, timezone, date

from coldledger.trace import (
    Item,
    Scan,
    Aggregation,
    Derivation,
    Handoff,
    PACK,
    UNPACK,
    OBSERVED,
    INFERRED,
    build_graph,
    possible_sources,
    forward_flow,
    custody_timeline,
    investigate,
    render_report,
    scan_diversion_risk,
)
from coldledger.compliance.license_registry import License

UTC = timezone.utc


def t(h, d=1):
    return datetime(2026, 10, d, h, tzinfo=UTC)


def base_items():
    return {
        "U1": Item("U1", "BIO", package=False, known=True),
        "U2": Item("U2", "BIO", package=False, known=True),
        "C1": Item("C1", "", package=True, known=True),
        "P1": Item("P1", "", package=True, known=True),
        "R1": Item("R1", "BIO", package=False, known=True),
    }


class TraceTests(unittest.TestCase):
    def _linear_events(self):
        # units -> case -> pallet, pallet moves across two handoffs,
        # then unpacked at the receiver.
        return [
            Aggregation("e1", t(8), "C1", "U1", PACK),
            Aggregation("e2", t(8, 1), "P1", "C1", PACK),
            Scan("e3", t(9), "P1", "MAKER", "DE"),
            Handoff("e4", t(10), "MAKER", "3PL", ("P1",), "DE", "S1"),
            Handoff("e5", t(14), "3PL", "HOSP", ("P1",), "DE", "S2"),
            Aggregation("e6", t(15), "P1", "C1", UNPACK),
            Aggregation("e7", t(15, 1), "C1", "U1", UNPACK),
            Scan("e8", t(16), "U1", "HOSP", "DE"),
        ]

    def test_multi_level_origin_confirmed(self):
        g = build_graph(self._linear_events(), base_items())
        origins, findings = possible_sources(g, "U1")
        self.assertEqual([o.serial for o in origins], ["U1"])
        # U1 itself is the root (never repacked); no structural uncertainty.
        self.assertTrue(origins[0].confirmed)
        self.assertEqual(findings, [])

    def test_inferred_carrier_marked_not_observed(self):
        g = build_graph(self._linear_events(), base_items())
        flow, _ = forward_flow(g, "U1")
        # U1 never appears on a manifest; both handoffs are inferred.
        self.assertEqual(flow, [
            ("MAKER", "3PL", INFERRED),
            ("3PL", "HOSP", INFERRED),
        ])
        # but the pallet itself is manifested/observed
        flow_p, _ = forward_flow(g, "P1")
        self.assertEqual(flow_p, [
            ("MAKER", "3PL", OBSERVED),
            ("3PL", "HOSP", OBSERVED),
        ])

    def test_timeline_segments_observed_and_inferred(self):
        licenses = [
            License(p, "DE", "BIO", date(2026, 1, 1), date(2026, 12, 31))
            for p in ("MAKER", "3PL", "HOSP")
        ]
        g = build_graph(self._linear_events(), base_items())
        facts, segments, findings = custody_timeline(g, "U1", licenses=licenses)
        parties = [(s.party, s.basis) for s in segments]
        # HOSP segment is upgraded to observed by the direct U1 scan.
        self.assertEqual(parties[-1], ("HOSP", OBSERVED))
        # 3PL never scanned U1 directly -> inferred segment.
        self.assertIn(("3PL", INFERRED), parties)
        self.assertEqual(findings, [])

    def test_repack_with_relabel_traces_through_derivation(self):
        events = [
            Aggregation("a1", t(8), "C1", "U1", PACK),
            Handoff("h1", t(10), "MAKER", "REPACKER", ("C1",), "DE", "S1"),
            Aggregation("a2", t(11), "C1", "U1", UNPACK),
            Derivation("d1", t(12), "R1", ("U1",)),
            Handoff("h2", t(13), "REPACKER", "HOSP", ("R1",), "DE", "S2"),
            Scan("s1", t(14), "R1", "HOSP", "DE"),
        ]
        g = build_graph(events, base_items())
        origins, findings = possible_sources(g, "R1")
        self.assertEqual([o.serial for o in origins], ["U1"])
        self.assertTrue(origins[0].confirmed)
        report = investigate(g, "R1")
        self.assertEqual(report.confirmed_origin.serial, "U1")

    def test_missing_node_is_reported_not_guessed(self):
        events = [
            # case C1 appears but is not in the master items
            Handoff("h1", t(10), "MAKER", "3PL", ("C1",), "DE", "S1"),
            Aggregation("a1", t(11), "C1", "U9", PACK),
        ]
        items = {"U9": Item("U9", "BIO", package=False, known=True)}
        g = build_graph(events, items)
        missing = {u.subject for u in g.uncertainties if u.code == "missing-node"}
        self.assertIn("C1", missing)
        origins, findings = possible_sources(g, "U9")
        # Packing is carriage, not identity: U9's origin is itself, but it is
        # unconfirmed because the package carrying it has no master record.
        self.assertEqual([o.serial for o in origins], ["U9"])
        self.assertFalse(origins[0].confirmed)
        codes = {u.code for u in findings}
        self.assertIn("missing-node", codes)

    def test_derivation_cycle_makes_origin_possible(self):
        events = [
            Derivation("d1", t(8), "A", ("B",)),
            Derivation("d2", t(9), "B", ("A",)),
        ]
        items = {
            "A": Item("A", "BIO", package=False, known=True),
            "B": Item("B", "BIO", package=False, known=True),
        }
        g = build_graph(events, items)
        origins, findings = possible_sources(g, "A")
        codes = {u.code for u in findings}
        self.assertIn("derivation-cycle", codes)
        # cyclic branch can never be a confirmed origin
        self.assertTrue(all(not o.confirmed for o in origins))

    def test_aggregation_self_nesting_cycle(self):
        events = [
            Aggregation("a1", t(8), "P1", "C1", PACK),
            Aggregation("a2", t(9), "C1", "P1", PACK),
        ]
        g = build_graph(events, base_items())
        codes = {u.code for u in g.uncertainties}
        self.assertIn("aggregation-cycle", codes)

    def test_custody_gap_on_unexplained_scan(self):
        events = [
            Scan("s1", t(8), "U1", "MAKER", "DE"),
            Scan("s2", t(12), "U1", "GREY_MARKET", "DE"),
        ]
        g = build_graph(events, base_items())
        report = investigate(g, "U1")
        codes = {u.code for u in report.findings}
        self.assertIn("custody-gap", codes)

    def test_observed_handoff_from_wrong_holder_is_break(self):
        events = [
            Scan("s1", t(8), "U1", "MAKER", "DE"),
            Handoff("h1", t(10), "IMPOSTOR", "HOSP", ("U1",), "DE", "S9"),
        ]
        g = build_graph(events, base_items())
        report = investigate(g, "U1")
        codes = {u.code for u in report.findings}
        self.assertIn("custody-break", codes)

    def test_seal_reuse_flagged(self):
        events = [
            Handoff("h1", t(10), "MAKER", "3PL", ("U1",), "DE", "SEAL-X"),
            Handoff("h2", t(12), "3PL", "HOSP", ("U1",), "DE", "SEAL-X"),
        ]
        g = build_graph(events, base_items())
        self.assertIn("seal-reuse", {u.code for u in g.uncertainties})

    def test_unauthorized_market_authorization(self):
        events = [
            Scan("s1", t(8), "U1", "MAKER", "DE"),
            Handoff("h1", t(10), "MAKER", "HOSP", ("U1",), "FR", "S1"),
        ]
        licenses = [
            License("MAKER", "DE", "BIO", date(2026, 1, 1), date(2026, 12, 31)),
            # HOSP has no FR authorization for BIO
        ]
        g = build_graph(events, base_items(), licenses=licenses)
        report = investigate(g, "U1", licenses=licenses)
        codes = {u.code for u in report.findings}
        self.assertIn("unauthorized-market", codes)
        # with a valid license the finding disappears
        licenses.append(License("HOSP", "FR", "BIO", date(2026, 1, 1), date(2026, 12, 31)))
        report2 = investigate(g, "U1", licenses=licenses)
        self.assertNotIn("unauthorized-market", {u.code for u in report2.findings})

    def test_report_distinguishes_confirmed_and_possible(self):
        events = [
            Aggregation("a1", t(8), "C1", "U1", PACK),
            Handoff("h1", t(10), "MAKER", "HOSP", ("C1",), "DE", "S1"),
        ]
        g = build_graph(events, base_items())
        text = render_report(investigate(g, "U1"))
        self.assertIn("possible (inferred", text)
        self.assertIn("CONFIRMED origin", text)

    def test_scan_diversion_risk_collects_hits(self):
        events = [
            Scan("s1", t(8), "U1", "MAKER", "DE"),
            Scan("s2", t(12), "U1", "GREY", "DE"),
        ]
        g = build_graph(events, base_items())
        hits = scan_diversion_risk(g)
        self.assertTrue(any(h.code == "custody-gap" for h in hits))


if __name__ == "__main__":
    unittest.main()
