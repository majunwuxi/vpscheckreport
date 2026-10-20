#!/usr/bin/env python3
import argparse,configparser,pathlib,smtplib,ssl,sys
from email.message import EmailMessage
p=argparse.ArgumentParser()
p.add_argument('--subject',required=True);p.add_argument('--body',required=True)
a=p.parse_args()
cfg=configparser.ConfigParser(interpolation=None)
cfg.read('/etc/vpscheckreport/mail.ini')
try:
 c=cfg['smtp'];m=EmailMessage()
 m['From']=c['from'];m['To']=c['to'];m['Subject']=a.subject
 m.set_content(pathlib.Path(a.body).read_text(encoding='utf-8'))
 security=c.get('security','starttls')
 if security not in ('starttls','ssl'):raise ValueError('TLS required')
 if security=='ssl':s=smtplib.SMTP_SSL(c['host'],int(c['port']),timeout=30,context=ssl.create_default_context())
 else:s=smtplib.SMTP(c['host'],int(c['port']),timeout=30)
 with s:
  if security=='starttls':s.starttls(context=ssl.create_default_context())
  if c['username']:s.login(c['username'],c['password'])
  s.send_message(m)
except Exception as e:
 print('Email failed:',type(e).__name__,str(e),file=sys.stderr);sys.exit(1)
