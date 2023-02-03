import pandas as pd
#import matplotlib.pyplot as plt
#import seaborn as sns
import datetime
from scipy import stats
from sklearn.ensemble import IsolationForest
import json
import subprocess
import binascii
import math
import string
import argparse
import plotly.graph_objects as go
from colorama import init, Fore, Back, Style
import base64
import re
import xml.etree.ElementTree as ET
import datetime

parser = argparse.ArgumentParser(description="EVTX analysis only mandatory arg is -f a EVTX file")
parser.add_argument("-f", dest='evtx',help='EVTX file')
parser.add_argument("-p", dest='phrase',help='Add an additional fishy phrase to search for. If in HTB CTF, use HTB', default='')
args = parser.parse_args()


# Read the XML file produced by evtx_dump.py
#xml_file = ET.parse(args.evtx)
#root = xml_file.getroot()
# Print the entire xml_file
#print(ET.tostring(xml_file.getroot(), encoding='utf8').decode('utf8'))
with open(args.evtx, 'r') as file:
    data = file.read()

events = data.split('\n\n')


### Dictionary of event ids and descriptions
event_ids = {
    4624: "An account was successfully logged on.",
    4625: "An account failed to log on.",
    4720: "A user account was created.",
    4722: "A user account was enabled.",
    4723: "An attempt was made to change an account's password.",
    4738: "A user account was changed.",
    4771: "Kerberos pre-authentication failed.",
    4648: "A logon was attempted using explicit credentials.",
    4740: "A user account was locked out.",
    4756: "A user account was deleted.",
    4769: "A Kerberos service ticket was requested.",
    4800: "The workstation was locked.",
    4801: "The workstation was unlocked."
}

Search_words = ["<!ENTITY",'whoami','echo','admin','root','power','Power','hostname','pwd','nc64.exe','error','pass','PASS', 'atob','WMIC', 'auth','denied','login','usr','success','psswd','pw','logon','key','cipher','sum','token','pin','fail','correct','restrict', 'cmd', 'sh', 'shell', 'exec', 'script', 'sethc', 'access', 'granted', 'denied', 'privilege', 'escalation', 'escalation attempt', 'firewall', 'intrusion', 'unauthorized', 'unauthorized access', 'network', 'breached', 'exploit', 'vulnerability', 'attack', 'malware', 'ransomware', 'encryption', 'decryption', 'hash', 'invalid', 'corrupted', 'file', 'malicious', 'payload', 'infected', 'mimikatz','.exe','.ps1','bypass','.vbs','Invoke-Command','Enter-PSSession','Mimikatz']

if args.phrase != '':
    Search_words.append(args.phrase)

usernames=[]
target_users=[]


df = pd.DataFrame()

fish_net=[]
### Main function to cycle through logs
for i,event in enumerate(events):

    fishy = []
    
    large_logs = []
    if len(event) > 6666:
        large_logs.append((i,len(event)))
    for word in Search_words:
        if word in event:
            fishy.append(word)
    if len(fishy)>0:
        fish_net.append((i,fishy))
    for line in event.splitlines():
        parts = line.strip().split("<")
        #print(parts)
        try:
            key, value = parts[1].split(">")
            if 'Correlation Activity' not in key and 'Time' not in key and 'Execution Process' not in key and len(parts)==3:
                df.at[i,key] = value
        except:
            #print('no')
            pass

def find_nans():
    for col in df.columns:
        nan_count = df[col].isnull().sum()
        # Print the result
        print("Number of NaN values in column ",col,": ", nan_count)



print(df.head)




def extract_timestamps(data):
    pattern = re.compile(r'<TimeCreated SystemTime="(.*?)"')
    timestamps = [datetime.datetime.strptime(x.group(1), '%Y-%m-%d %H:%M:%S.%f') for x in re.finditer(pattern, data)]
    return timestamps

timestamps = extract_timestamps(data)

if timestamps:
    first_timestamp = min(timestamps)
    last_timestamp = max(timestamps)
    duration = last_timestamp - first_timestamp
    print(f"The log duration is: {duration}")
else:
    print("No timestamps found.")




### This begins the output 



################################
# Continue to print terminal output
# Print the top border
print(Fore.CYAN+"╔" + "══" * 15 + "╗")

# Print the title
print("║" + " " * 6 +Fore.MAGENTA+ "Summary Statistics" +Style.RESET_ALL+ Fore.CYAN+" " * 6 + "║")

# Print the bottom border
print("╚" + "══" * 15 + "╝"+Style.RESET_ALL)

print('The total number of Events: ',len(events))

# Display the total number of dataframes
print("")
print("")
print('The total number of logs is:',df.shape[0])

# Print the difference in a human-readable format
#print(f'Total time: {difference}')
print("")

names = ["Computer",'Data Name="WorkstationName"','SubjectUserName','SubjectDomainName','SubjectLogonId','Data Name="SubjectUserName"','Data Name="TargetUserName"','Data Name="SamAccountName"']
for name in names:
    if name in df.columns:
        print('yee')
    try:
        unique_values = df[name].drop_duplicates()
        # Print the unique values for Computer
        print("Unique '{}':".format(name))
        print(unique_values)
    except:
        pass
if len(fish_net)>0:
    print('Fish net!!')
for catch in fish_net:
  if len(catch[1])>4:
      print(catch)

#for col in df.columns:
#    print(col)


#Data Name="AuthenticationPackageName"


print('hi')
