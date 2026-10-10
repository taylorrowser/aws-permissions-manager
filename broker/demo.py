"""One-command, deterministic synthetic walkthrough; never prints session handles."""
import json
from pathlib import Path
import tempfile
from broker import Store, Executor, FakeSTS, CATALOG

def main():
    with tempfile.TemporaryDirectory() as directory:
        now=[1_800_000_000]
        s=Store(Path(directory)/'demo.sqlite3',lambda:now[0]); executor=Executor(s); sts=FakeSTS(s)
        request=s.submit('demo-agent',{'roles':list(CATALOG),'reason':'Compare synthetic Plants preview and live inventory',
                                     'ttl_seconds':60,'task_environment':'preview'})
        rid=request['id']; approval=s.decide('demo-owner',rid,'approve',request['digest'])
        pending=executor.execute(rid,timeout_after_write=True)
        restarted=Executor(Store(s.path,lambda:now[0]))
        reconciled=restarted.execute(rid)
        applied=restarted.execute(rid)
        reads=[]
        sessions=[]
        for role in request['manifest']['roles']:
            session=sts.vend('demo-agent',rid,role);sessions.append(session)
            reads.append({'role':role,'result':sts.read('demo-agent',session['session_id'],CATALOG[role]['resources'][1])})
        now[0]+=60
        from broker import Denied
        try:
            sts.read('demo-agent',sessions[0]['session_id'],CATALOG[sessions[0]['role']]['resources'][1])
            cutoff='FAIL'
        except Denied:
            cutoff='PASS: existing session denied at exact cutoff; no cleanup ran'
        rejected=s.submit('demo-agent',{'roles':['preview-read'],'reason':'Synthetic rejection example','ttl_seconds':60,'task_environment':'preview'})
        rejected=s.decide('demo-owner',rejected['id'],'reject',rejected['digest'])
        evidence={'simulation_only':True,'request':request,'approval_state':approval['state'],
                  'timeout_state':pending['state'],'read_only_reconciliation':reconciled,'applied_result':applied,'approved_bundle_reads':reads,
                  'effective_cutoff':cutoff,'final_status':s.status('demo-agent',rid),
                  'rejected_state':rejected['state'],'session_bodies_saved':False}
        Path('evidence/demo-results.json').write_text(json.dumps(evidence,indent=2)+'\n')
        print(json.dumps({'simulation_only':True,'request_state':request['state'],
                          'approval_state':approval['state'],'execution_state':applied['state'],
                          'selected_roles':[x['role'] for x in reads], 'cutoff':cutoff,
                          'rejected_state':rejected['state'], 'evidence':'evidence/demo-results.json'},indent=2))

if __name__=='__main__':main()
