"""Explainable serialization traceability across aggregation and custody changes.

Links four record families that normally live in separate one-hop views:
serial scans, aggregation (pack / unpack / repack), custody handoffs and market
authorizations. Missing nodes and cycles are reported as uncertainty instead of
being treated as confirmed provenance.
"""
