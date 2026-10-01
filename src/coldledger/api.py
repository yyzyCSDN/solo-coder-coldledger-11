from datetime import timedelta
from .inventory.fefo import reserve
from .quality.release import may_release
from .transport.connections import choose
from .trace import build_graph, investigate, render_report, scan_diversion_risk
class ColdLedgerService:
    def reserve_inventory(self,*args,**kwargs): return reserve(*args,**kwargs)
    def release_decision(self,*args,**kwargs): return may_release(*args,**kwargs)
    def next_connection(self,inbound,candidates,minutes): return choose(inbound,candidates,timedelta(minutes=minutes))
    def build_trace(self,events,items=None,licenses=None):
        return build_graph(events,items=items,licenses=licenses)
    def trace_serial(self,graph,serial,licenses=None):
        return investigate(graph,serial,licenses)
    def render_trace(self,report): return render_report(report)
    def scan_diversion_risk(self,graph,licenses=None):
        return scan_diversion_risk(graph,licenses)
    def health(self): return {'service':'coldledger','status':'ok','runtime_dependencies':0}
