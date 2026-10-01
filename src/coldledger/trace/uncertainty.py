from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

# Reasons why a trace path cannot be treated as confirmed provenance.
MISSING_NODE = "missing_node"              # referenced unit has no record
MISSING_CONTENTS = "missing_contents"      # container contents never declared
CUSTODY_GAP = "custody_gap"                # party moved a unit it did not hold
CYCLE = "cycle"                            # provenance walk revisited a state
CONFLICT = "conflict"                      # contradictory records / time order
UNVERIFIED_SEAL = "unverified_seal"        # handoff without a usable seal
MULTIPLE_ORIGINS = "multiple_origins"      # more than one possible source
UNAUTHORIZED_MARKET = "unauthorized_market"  # sale/export without valid auth
UNKNOWN_PRODUCT = "unknown_product"        # cannot resolve product for auth check


@dataclass(frozen=True)
class Uncertainty:
    code: str
    detail: str
    at: datetime | None = None
    ref: str | None = None
    node: str | None = None

    def explain(self) -> str:
        where = f" [{self.ref}]" if self.ref else ""
        when = f" @ {self.at.isoformat()}" if self.at else ""
        who = f" node={self.node}" if self.node else ""
        return f"{self.code}{where}{when}{who}: {self.detail}"
