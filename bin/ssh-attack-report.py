#!/usr/bin/env python3
"""Count SSH authentication failures and fail2ban bans in Beijing day-window."""
import argparse,collections,datetime as dt,gzip,ipaddress,json,pathlib,re,subprocess,sys
from zoneinfo import ZoneInfo
TZ=ZoneInfo('Asia/Shanghai')
P=[re.compile(r'Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?\S+ from ([0-9a-fA-F:.]+) port'),re.compile(r'Invalid user \S+ from ([0-9a-fA-F:.]+)'),re.compile(r'maximum authentication attempts exceeded for .* from ([0-9a-fA-F:.]+) port',re.I)]
MONTHS={x:i+1 for i,x in enumerate('Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split())}
def category(s):
 try:
  ip=ipaddress.ip_address(s)
  return 'shared_or_tailnet' if ip in ipaddress.ip_network('100.64.0.0/10') else ('public' if ip.is_global else 'private_or_reserved')
 except ValueError:return None
def period(now):
 n=now.astimezone(TZ);end=dt.datetime.combine(n.date(),dt.time(1),TZ)
 if n<end:end-=dt.timedelta(days=1)
 return end-dt.timedelta(days=1),end
def journal(start,end):
 cmd=['journalctl','--no-pager','-o','json','--since',start.astimezone(dt.timezone.utc).isoformat(),'--until',end.astimezone(dt.timezone.utc).isoformat(),'_COMM=sshd']
 q=subprocess.run(cmd,capture_output=True,text=True,timeout=40)
 if q.returncode:raise RuntimeError(q.stderr or 'journal query failed')
 for line in q.stdout.splitlines():
  try:
   x=json.loads(line);t=dt.datetime.fromtimestamp(int(x['__REALTIME_TIMESTAMP'])/1e6,dt.timezone.utc).astimezone(TZ)
   if start<=t<end:yield x.get('MESSAGE','')
  except (ValueError,KeyError,TypeError):pass
def reader(path):
 with (gzip.open(path,'rt',errors='replace') if str(path).endswith('.gz') else open(path,errors='replace')) as f:yield from f
def authlogs(start,end,root):
 paths=list(pathlib.Path(root).glob('auth.log*'))
 if not paths:raise RuntimeError('auth.log missing')
 for path in paths:
  for line in reader(path):
   m=re.match(r'^([A-Z][a-z]{2})\s+(\d+)\s+(\d\d:\d\d:\d\d)\s+',line)
   if not m or 'sshd[' not in line:continue
   try:
    year=start.year;month=MONTHS[m[1]];clock=dt.time.fromisoformat(m[3])
    candidates=[dt.datetime(y,month,int(m[2]),clock.hour,clock.minute,clock.second).astimezone().astimezone(TZ) for y in (year-1,year,year+1)]
    stamp=min(candidates,key=lambda x:abs((x-start).total_seconds()))
    if start<=stamp<end:yield line
   except (ValueError,KeyError):continue
def count_fail(records):
 c=collections.Counter()
 for msg in records:
  for p in P:
   m=p.search(msg)
   if m and category(m[1]):c[m[1]]+=1;break
 return c
def bans(start,end,root):
 c=collections.Counter();paths=list(pathlib.Path(root).glob('fail2ban.log*'))
 if not paths:return c,False
 for path in paths:
  for line in reader(path):
   m=re.match(r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),',line)
   if not m:continue
   try:t=dt.datetime.strptime(m[1],'%Y-%m-%d %H:%M:%S').astimezone().astimezone(TZ)
   except ValueError:continue
   if not start<=t<end:continue
   hit=re.search(r'fail2ban\.actions.*?\bBan\s+([0-9a-fA-F:.]+)\b',line)
   if hit and category(hit[1]):c[hit[1]]+=1
 return c,True
def main():
 a=argparse.ArgumentParser();a.add_argument('--json-output');a.add_argument('--logs-root',default='/var/log');a.add_argument('--now');v=a.parse_args()
 start,end=period(dt.datetime.fromisoformat(v.now) if v.now else dt.datetime.now(TZ))
 errors=[]
 try:failed=count_fail(journal(start,end));source='journal'
 except Exception as e:
  errors.append(str(e))
  try:failed=count_fail(authlogs(start,end,v.logs_root));source='auth.log'
  except Exception as e:failed=None;source=None;errors.append(str(e))
 try:ban,ban_ok=bans(start,end,v.logs_root)
 except Exception as e:ban=collections.Counter();ban_ok=False;errors.append(str(e))
 rows=[dict(ip=ip,failed=(failed or {}).get(ip,0),bans=ban.get(ip,0),category=category(ip)) for ip in (set(failed or {})|set(ban))]
 rows.sort(key=lambda r:(-r['failed'],-r['bans'],r['ip']))
 out=dict(schema=1,host=__import__('socket').gethostname(),start=start.isoformat(),end=end.isoformat(),source=source,failures_available=failed is not None,bans_available=ban_ok,failed_total=sum(failed.values()) if failed is not None else None,bans_total=sum(ban.values()) if ban_ok else None,rows=rows,warnings=errors)
 if v.json_output:
  path=pathlib.Path(v.json_output);path.parent.mkdir(parents=True,exist_ok=True)
  path.write_text(json.dumps(out,ensure_ascii=False,indent=2));path.chmod(0o600)
 print('SSH Attack Report | Beijing',start.isoformat(),'to',end.isoformat())
 print('SSH failures:',out['failed_total'] if failed is not None else 'unavailable')
 print('Fail2ban bans:',out['bans_total'] if ban_ok else 'unavailable')
 for r in [x for x in rows if x['category']=='public'][:10]:print(r['ip'],'failed',r['failed'],'banned',r['bans'])
 if not rows:print('No matching records, or insufficient data.')
 for e in errors:print('WARNING',e)
 return 0 if failed is not None else 2
if __name__=='__main__':sys.exit(main())
