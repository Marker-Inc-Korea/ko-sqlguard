import sys; sys.path.insert(0,'src')
import sqlglot
from ko_sqlguard import GuardPolicy, Verdict, check
from ko_sqlguard.checks.tautology import _lit, _CMP
POL=GuardPolicy()
def pf(sql):
    for d in (POL.dialect,*POL.fallback_dialects):
        try: return sqlglot.parse(sql, read=d)
        except Exception: continue
    return None
def fires(sql):
    st=pf(sql)
    if not st: return 'PARSEFAIL'
    for s in st:
        if s is None: continue
        for n in s.find_all(*_CMP.keys()):
            if _lit(n.this) is not None and _lit(n.expression) is not None:
                return n.sql()
    return None
def cur(sql):
    try: return check(sql,policy=POL).verdict is Verdict.BLOCK
    except Exception: return True
ms=[l for l in open('_m.txt').read().splitlines() if l.strip()]
c=a=0; L=[]
for m in ms:
    f=fires(m); cb=cur(m)
    if f and f!='PARSEFAIL': c+=1
    if cb: a+=1
    L.append(('FIRE' if (f and f!='PARSEFAIL') else '----')+' blk=%-5s '%cb+'%-18s'%str(f)[:18]+' | '+m[:52])
L.append('misses=%d fires=%d curblocked=%d'%(len(ms),c,a))
open('_res.txt','w').write("\n".join(L))
