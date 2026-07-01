import sys; sys.path.insert(0,"src")
from ko_sqlguard import check, GuardPolicy
from sqlglot import parse_one, exp
tests = [
 "select case when 6558=4327 then 1 else null end",
 "select (case when (3855=3855) then 3855 else 1/(select 0) end)",
 "1 union all select null,null,null,null",
 "-5891 union all select 7103,7103,7103,7103",
 "select count(*) from generate_series(1,5000000)",
 "select case when status='active' then 1 else 0 end from users",
 "select sum(case when amount>100 then 1 else 0 end) from orders",
 "select 1 as one, name from users",
 "select a from t1 union select b from t2",
 "SELECT o.OrgName FROM Organizations o CROSS JOIN OrgDonations d WHERE o.OrgID = d.OrgID",
]
for t in tests:
    v=check(t,policy=GuardPolicy())
    print("%-9s %s  <- %s" % (v.verdict.value,[x.code for x in v.violations],t[:58]))
print("---- lit=lit / setop-arm ----")
for p in ["select case when 6558=4327 then 1 else null end","1 union all select null,null,null",
          "select a from t1 union select b from t2"]:
    e=parse_one(p, read="postgres")
    lits=[c.sql() for c in e.find_all(exp.EQ) if isinstance(c.this,exp.Literal) and isinstance(c.expression,exp.Literal)]
    for u in e.find_all(exp.Union):
        larm=type(u.this).__name__
        print("UNION left-arm:", larm, "|", p[:35])
    print(p[:35],"| litEQ:",lits)
