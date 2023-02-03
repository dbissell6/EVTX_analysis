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
from collections import Counter

parser = argparse.ArgumentParser(description="EVTX analysis only mandatory arg is -f a txt file converted from a EVTX file ")

parser.add_argument("-f", dest='evtx',help='EVTX file')
parser.add_argument("-p", dest='phrase',help='Add an additional fishy phrase to search for. If in HTB CTF, use HTB. For multiple comma seperated no space "HTB,PICOCTF,FLAG"', default='')
parser.add_argument("-rp", dest='remove_phrase',help='Remove a fishy phrase to search for. They can get noisy. For multiple comma seperated no space "HTB,PICOCTF,FLAG"', default='')
parser.add_argument("-fc", dest='fish_count',help='Sometimes theres are too many fish, only look at catches with more than x fish. Default is 2', default='2')
args = parser.parse_args()


# fire - pcap
# wind - log
# earth - registry
# lighting - memory cap
# water - 

###Print Header

# Initialize colorama
init()

### print multicolors
colors = [1, 11, 41, 14, 27, 57]

# Define the string to color

string="""
vvvvvvvvvv~~~vvvvvvvvvvvvvvvvvvvvvvv~~vvvvvvvvvvvvv~~~vvvvvvvvvvvvvvvvv~w~vvvvvvvvvvvvvvvvvvvv~~~vvvvvvvvvvvvvv~~~vvvvvvv
vvvvvvvvvvvvvbddddbvvvvvvvvvvv ~B~SSPPP~Bw   ~wBC~S~~S~CB~  vvvvvvvvvvvvvbddddbvvvvvvvvvvv ~B~SSPPP~Bw   ~wBC~S~~S~CB~  
vvvvvvvvvvvvvvbbbaBbvvbbbbvvvv~dS ~BwwB~PdS SBCS  S~~~S Pdw vvvvvvvvvvvvvvbbbaBbvvbbbbvvvv~dS ~BwwB~PdS SBCS  S~~~S Pdw 
vvvvvvvvvvvvvvvvvvddvvaddddbvvBC ~dw  Cw~dS~Bw   wB~P~Bw PdSvvvvvvvvvvvvvvvvvvddvvaddddbvvBC ~dw  Cw~dS~Bw   wB~P~Bw PdS
vvvvvvvvvvvvvvvvvbBavvvvvbddvvCB  ~BC~wCBP ~d~  PaP~S~CB SdSvvvvvvvvvvvvvvvvvbBavvvvvbddvvCB  ~BC~wCBP ~d~  PaP~S~CB SdS
baaaaaaa~~~~aaaadBavvvvvvvbBbvSBw~ ~P~PS   ~dS  Sdw~CCwSPBw baa~~~aaaaaaaaaadBavvvvvvvbBbvSBw~ ~P~PS   ~dS  Sdw~CCwSPBw 
baaaaaa~v~aaaaaabbvvvvvvvbddvv SCB~S~   ~S~BBCCP~SCCwwwCC~  baaaaaa~v~aaa~aaaaaaabbvvbddvv SCB~S~   ~S~BBCCP~SCCwwwCC~  
bd~~~ddd~v~vddddddddddddddabvv   S~CCCCCCC~S ~PCBP SPPPS    bd~~ddd~v~vddddddddddddddabvv   S~CCCCCCC~S ~PCBP SPPPS    
vbbb~v~vbbbbbbbbbbbbbbbbbvvvvv       ~~~SPPSS   Pd~         vbbb~v~vbbbbbbbbbbbbbbbbbvvvvv       ~~~SPPSS   Pd~         
bddddddddddddddddddddbvvvvvvvv        SCCwwCCCS  ~d~        bddddddddddddddddddddbvvvvvvvv        SCCwwCCCS  ~d~        
vvvvvvvvvvvvvvvvvvvbaBbvvvvvvv       SdwSCC~~BC  SaP        vvvvvvvvvvvvvvvvvvvbaBbvvvvvvv       SdwSCC~~BC  SaP        
vvvvvvvvvvvvvvvvvvvvvBavvvvvvv       Pa~~dS SBC  PdS        vvvvvvvvvvvvvvvvvvvvvBavvvvvvv       Pa~~dS SBC  PdS        
vvvvvvvvvvvvvvvvvvvvaBbvvvvvvv       Sd~ ~CCCw~ SBw         vvvvvvvvvvvvvvvvvvvvaBbvvvvvvv       Sd~ ~CCCw~ SBw         
vvvvvvvvvvvvvvvvbddddbvvvvvvvv        PBCPSS~~PwB~          vvvvvvvvvvvvvvvvbddddbvvvvvvvv        PBCPSS~~PwB~          
vvvvvvvvvvvvvvvvvbbbvvvvvvvvvv         ~~wCCCCw~~           vvvvvvvvvvvvvvvvvbbbvvvvvvvvvv         ~~wCCCCw~~  
"""

# Iterate over the characters in the string
for i, char in enumerate(string):
    if char == 'v':
        print("\033[30m" + ' ', end="")
    else:
    # Set the color for the current character
        print("\033[38;5;" + str(colors[i % len(colors)]) + "m" + char, end="")
        

###Begin printing and outputing data
# Descritpion text
print("\033[0m")
print("")
print("")
print(Fore.BLUE+"This is a EVTX analyzer with 3 basic steps:\n1) Show summary statistics and visualize.\n2) Examine the content of events and look for anything fishy.\n3) Perform a time series anomaly detection algorithm to find fishy events."+Style.RESET_ALL)
print("")
print("")
print(Fore.BLUE+'General EVTX reminders and tricks for ctfs\n '+Style.RESET_ALL)
print("")
print("")



# Read the XML file produced by evtx_dump.py
#xml_file = ET.parse(args.evtx)
#root = xml_file.getroot()
# Print the entire xml_file
#print(ET.tostring(xml_file.getroot(), encoding='utf8').decode('utf8'))
with open(args.evtx, 'r') as file:
    data = file.read()

events = data.split('</Event>')


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
    4801: "The workstation was unlocked.",
    4634: "An account was logged off.",
    4635: "The account was logged off, and the logon session was terminated.",
    4657: "A registry value was modified.",
    4703: "A user right was assigned.",
    4704: "A user right was removed.",
    4706: "A new trust was created to a domain.",
    4707: "A trust to a domain was removed.",
    4724: "An attempt was made to reset an account's password.",
    4725: "An account failed to log on.",
    4726: "A user account was deleted.",
    4728: "A member was added to a security-enabled global group.",
    4729: "A member was removed from a security-enabled global group.",
    4759: "The cryptologic function has been executed.",
    5024: "The Windows Firewall Service has started successfully.",
    5025: "The Windows Firewall Service has been stopped.",
    5031: "The Windows Firewall has blocked an application from accepting incoming connections on the network."
}

Search_words = ["<!ENTITY",'whoami','echo','admin','root','power','Power','hostname','pwd','nc64.exe','error','pass','PASS', 'atob','WMIC', 'auth','denied','login','usr','success','psswd','pw','logon','key','cipher','sum','token','pin','fail','correct','restrict', 'cmd', 'sh', 'shell', 'exec', 'script', 'sethc', 'access', 'granted', 'denied', 'privilege', 'escalation', 'escalation attempt', 'firewall', 'intrusion', 'unauthorized', 'unauthorized access', 'network', 'breached', 'exploit', 'vulnerability', 'attack', 'malware', 'ransomware', 'encryption', 'decryption', 'hash', 'invalid', 'corrupted', 'file', 'malicious', 'payload', 'infected', 'mimikatz','.exe','.ps1','bypass','.vbs','Invoke-Command','Enter-PSSession','Mimikatz']

### add fishy phrase
if args.phrase != '':
    if ',' in args.phrase:
        Search_words.extend(args.phrase.split(','))
    else: 
        Search_words.append(args.phrase)

### remove fishy phrase
if args.remove_phrase != '':
    if ',' in args.remove_phrase:
        rm = args.remove_phrase.split(',')
        for word in rm:
            Search_words.remove(word)
    else: 
        Search_words.remove(args.remove_phrase)



usernames=[]
target_users=[]


df = pd.DataFrame()

fish_net=[]
### Main function to cycle through logs ##########################
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



#print(df.head(10))
# Create a dictionary to store each event ID with its rows
events_dict = {}

# Iterate through each row of the DataFrame
for index, row in df.iterrows():
    # Get the value of the EventID column for the current row
    if pd.isna(row['EventID Qualifiers=""']):
        # Handle the case where EventID Qualifiers is NaN
        continue
    else:
        event_id = int(row['EventID Qualifiers=""'])
        

    # If the event ID is not yet in the dictionary, add it and store the row as a list
    if event_id not in event_ids:
        continue
    else:
        if event_id not in events_dict:
            events_dict[int(event_id)] = [index]
        # If the event ID is already in the dictionary, add the current row to the list of rows for that event ID
        else:
            events_dict[int(event_id)].append(index)

# Iterate through each event ID in the dictionary
#print(events_dict)
for event_id, rows in events_dict.items():
    # Print the event ID, its description, and the list of rows for that event ID
    print(Fore.RED +Back.YELLOW+"!Here, Fishy Fishy Fishy!"+Style.RESET_ALL)	
    print("Event ID:", event_id)
    print("Description:", event_ids[int(event_id)])
    if len(rows) > 10:
        print("There are ", len(rows),' events with this ID')
    else: 
    	print("Events:", rows)

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
if len(fish_net)>1:
    print(Fore.RED +Back.YELLOW+"!Found some fishys!"+Style.RESET_ALL)	

#for catch in fish_net:
#  if len(catch[1])>int(args.fish_count):
#      print(catch)
   
   
   
      
all_words = []

for net in fish_net:
    all_words.extend(net[1])

word_counts = Counter(all_words)

for word, count in word_counts.items():
    print(f"{word}: {count}")

#for col in df.columns:
#    print(col)
#Data Name="AuthenticationPackageName"


print('hi')
