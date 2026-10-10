"""Run the suite and persist only case names, outcomes and failure tracebacks."""
import datetime
import json
from pathlib import Path
import unittest

class Results(unittest.TextTestResult):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs);self.cases=[]
    def addSuccess(self,test):
        super().addSuccess(test);self.cases.append({'test':test.id(),'status':'pass'})
    def addFailure(self,test,err):
        super().addFailure(test,err);self.cases.append({'test':test.id(),'status':'fail'})
    def addError(self,test,err):
        super().addError(test,err);self.cases.append({'test':test.id(),'status':'error'})

if __name__=='__main__':
    suite=unittest.defaultTestLoader.discover('tests')
    result=unittest.TextTestRunner(verbosity=2,resultclass=Results).run(suite)
    evidence={'simulation_only':True,'timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'tests_run':result.testsRun,'passed':result.wasSuccessful(),'cases':result.cases,
              'failures':[{'test':t.id(),'traceback':trace} for t,trace in result.failures+result.errors]}
    Path('evidence').mkdir(exist_ok=True)
    Path('evidence/test-results.json').write_text(json.dumps(evidence,indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
