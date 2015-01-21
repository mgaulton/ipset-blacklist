import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email import Encoders
import os
import re
import subprocess
import urllib
import os
import time
import shutil
import logging
import logging.handlers
import sys

rulechain = sys.argv[1]

proc = subprocess.Popen("iptables -L INPUT | grep 'match-set'", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
checker = proc.stdout.readlines()
matched = 'no'
if any(rulechain in s for s in checker):
  matched = 'yes'
  print 'rule found'
if matched == 'no':
    print 'Rule not found'
    subprocess.Popen("iptables -I INPUT 1 -m set --match-set %s src -p TCP -m multiport --dports 22,80,443 -j REJECT" % rulechain, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
