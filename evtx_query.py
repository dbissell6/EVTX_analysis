import pandas as pd
import datetime
import subprocess
import binascii
import string
import argparse
import datetime

parser = argparse.ArgumentParser(description="EVTX analysis only mandatory arg is -f a EVTX file")
parser.add_argument("-f", dest='evtx',help='EVTX file')
parser.add_argument("-l", dest='log',help='This is the log number to print', default='')
args = parser.parse_args()

with open(args.evtx, 'r') as file:
    data = file.read()

events = data.split('</Event>')

if ',' in args.log:
    for thing in args.log.split(','):
        print(events[int(thing)])
        print('\n***\n')    
else:
    print(events[int(args.log)])
