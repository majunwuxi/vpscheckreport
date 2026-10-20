import importlib.util
import pathlib
import tempfile
import unittest
from datetime import datetime
from zoneinfo import ZoneInfo

script=pathlib.Path(__file__).resolve().parents[1]/'bin/ssh-attack-report.py'
spec=importlib.util.spec_from_file_location('attack',script)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class AttackTest(unittest.TestCase):
 def test_window(self):
  _,end=m.window(datetime(2026,10,20,0,15,tzinfo=ZoneInfo('Asia/Shanghai')))
  self.assertEqual(end.isoformat(),'2026-10-19T01:00:00+08:00')
  _,end=m.window(datetime(2026,10,20,1,15,tzinfo=ZoneInfo('Asia/Shanghai')))
  self.assertEqual(end.isoformat(),'2026-10-20T01:00:00+08:00')
 def test_public(self):
  self.assertEqual(m.ip_class('100.100.1.1'),'tailnet_or_cgnat')
  self.assertEqual(m.ip_class('8.8.8.8'),'public')
  self.assertEqual(m.ip_class('192.168.1.2'),'non_public')
 def test_no_double_count_invalid_user(self):
  records=[(None,'Invalid user admin from 8.8.8.8 port 22'),(None,'Failed password for invalid user admin from 8.8.8.8 port 123 ssh2')]
  self.assertEqual(m.collect_failures(records)['8.8.8.8'],1)
 def test_gzip(self):
  import gzip
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/'auth.log.1.gz'
   with gzip.open(p,'wt') as f:f.write('hello\n')
   self.assertEqual(list(m.read_file(p)),['hello\n'])

if __name__=='__main__':unittest.main()
