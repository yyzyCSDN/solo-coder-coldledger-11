from datetime import timedelta
from .inventory.fefo import reserve
from .quality.release import may_release
from .transport.connections import choose
from .trace.builder import GraphBuilder
from .trace.engine import Tracer
from .trace.model import Commission, Handoff, MarketAuth, Pack, Repack, Scan, Unpack
class ColdLedgerService:
    def reserve_inventory(self,*args,**kwargs): return reserve(*args,**kwargs)
    def release_decision(self,*args,**kwargs): return may_release(*args,**kwargs)
    def next_connection(self,inbound,candidates,minutes): return choose(inbound,candidates,timedelta(minutes=minutes))
    def build_trace_graph(self,records,auths=None): return GraphBuilder().build(records,auths)
    def trace_back(self,serial,records,auths=None,as_of=None):
        return Tracer(self.build_trace_graph(records,auths)).trace_back(serial,as_of)
    def trace_forward(self,serial,records,auths=None,as_of=None):
        return Tracer(self.build_trace_graph(records,auths)).trace_forward(serial,as_of)
    def health(self): return {'service':'coldledger','status':'ok','runtime_dependencies':0}
