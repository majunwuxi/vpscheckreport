#!/usr/bin/env python3
"""Fail-closed Tailscale SSH isolation check; local firewall only."""
import argparse,re,subprocess,sys

def cmd(args):
 p=subprocess.run(args,text=True,capture_output=True,timeout=12)
 if p.returncode: raise ValueError(args[0]+' failed')
 return p.stdout

def check_family(raw,port,v6=False):
 chains={};policy={}
 for line in raw.splitlines():
  if line.startswith('-P '):
   _,name,val=line.split();policy[name]=val
  elif line.startswith('-N '):chains[line.split()[1]]=[]
  elif line.startswith('-A '):
   _,name,expr=line.split(' ',2);chains.setdefault(name,[]).append(expr)
 if policy.get('INPUT')!='DROP':raise ValueError('INPUT not default DROP')
 before='ufw6-before-input' if v6 else 'ufw-before-input'
 user='ufw6-user-input' if v6 else 'ufw-user-input'
 main=chains.get('INPUT',[])
 if not main or main[0]!='-j ts-input' or '-j '+before not in main:raise ValueError('unexpected INPUT order')
 for r in main[1:main.index('-j '+before)]:
  if r not in ('-j ufw-before-logging-input','-j ufw6-before-logging-input') or chains.get(r[3:],[]):raise ValueError('unknown early INPUT rule')
 ts=chains.get('ts-input',[])
 if '-i tailscale0 -j ACCEPT' not in ts:raise ValueError('no Tailscale ACCEPT')
 for r in ts:
  if not any(re.fullmatch(p,r) for p in (
   r'-s [0-9a-fA-F.:/]+ -i lo -j ACCEPT',r'-i tailscale0 -j ACCEPT',
   r'-p udp -m udp --dport 41641 -j ACCEPT',
   r'-s [0-9a-fA-F.:/]+ ! -i tailscale0 -j (RETURN|DROP)')):
   raise ValueError('unknown Tailscale rule')
 rules=chains.get(user,[])
 if len(rules)<2 or rules[:2]!=['-i tailscale0 -j ACCEPT',f'-p tcp -m tcp --dport {port} -j DROP']:
  raise ValueError('missing ordered Tailscale allow / SSH drop')
 pre=chains.get(before,[])
 if '-j '+user not in pre:raise ValueError('UFW user chain unreachable')
 for r in pre[:pre.index('-j '+user)]:
  if not (r in ('-i lo -j ACCEPT','-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
   '-m conntrack --ctstate INVALID -j ufw-logging-deny',
   '-m conntrack --ctstate INVALID -j ufw6-logging-deny',
   '-m conntrack --ctstate INVALID -j DROP','-m rt --rt-type 0 -j DROP',
   '-j ufw-not-local','-p udp -m udp --sport 67 --dport 68 -j ACCEPT')
   or re.fullmatch(r'-p (icmp|ipv6-icmp) .+ -j ACCEPT',r)
   or re.fullmatch(r'-s fe80::/10 -p ipv6-icmp .+ -j ACCEPT',r)
   or re.fullmatch(r'-s fe80::/10 -d fe80::/10 -p udp .+ -j ACCEPT',r)
   or re.fullmatch(r'-d (224\.0\.0\.251/32|239\.255\.255\.250/32|ff02::fb/128|ff02::f/128) -p udp .+ -j ACCEPT',r)):
   raise ValueError('unknown pre-user rule: '+r)
 if not v6:
  nl=chains.get('ufw-not-local',[])
  if not nl or any('-j ACCEPT' in x for x in nl):raise ValueError('unknown ufw-not-local')
 return True

def check_nft(raw):
 table=None
 for line in raw.splitlines():
  m=re.match(r'^table (\S+) (\S+) \{',line)
  if m:table=m.groups()
  if re.search(r'\bhook (input|prerouting|ingress)\b',line):
   if not table or table[0] not in ('ip','ip6'):raise ValueError('unknown nft hook family')
   if 'hook input' in line and table[1]=='filter' and 'priority filter; policy drop;' in line:continue
   if 'hook input' in line and table[1]=='mangle' and 'priority mangle; policy accept;' in line:continue
   if 'hook prerouting' in line and table[1] in ('nat','mangle'):continue
   if 'hook input' in line and table[1]=='nat':continue
   raise ValueError('unknown nft ingress hook')
 for family in ('ip','ip6'):
  if not re.search(r'table '+family+r' filter \{.*?hook input priority filter; policy drop;',raw,re.S):
   raise ValueError('missing nft input drop hook')

def verify(v4,v6,nft,port):
 if not 1<=port<=65535:raise ValueError('invalid port')
 check_family(v4,port);check_family(v6,port,True);check_nft(nft)
 return 'PASS: IPv4/IPv6 Tailscale-only local firewall paths verified; external reachability not tested'

def main():
 a=argparse.ArgumentParser();a.add_argument('--port',required=True,type=int);args=a.parse_args()
 try:print(verify(cmd(['iptables','-S']),cmd(['ip6tables','-S']),cmd(['nft','list','ruleset']),args.port))
 except (ValueError,OSError,subprocess.TimeoutExpired) as e:
  print('WARN: SSH isolation unverified: '+str(e));return 1
 return 0
if __name__=='__main__':sys.exit(main())
