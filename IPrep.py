


#https://auth0.com/signals/ip //  Free to create account and get API Key
#abuseIPDB // Free to create account and API
#OTX // Free to create account and API

import json
import requests
import numpy as np
import pandas as pd
import yaml
import re



address = raw_input('What IP would you like to see results for? ').strip()
arr = []
arr2 = []
arr3 = []
arr4 = []
arr5 = []
arr6 = []
arr7 = []


def abuseIPDB(address):
    API_KEY= 'YOUR_API_KEY'
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {'ipAddress': str(address),'maxAgeInDays': '90', 'verbose': True}
    headers = {'Accept': 'application/json','Key': API_KEY}
    r = requests.request(method='GET', url=url, headers=headers, params=querystring)
    response = json.loads(r.text)
    #print json.dumps(response, sort_keys=True, indent=4)
    if response['data']['isWhitelisted'] == True:
        print 'According to AbuseIPDB this IP is whitelisted'
        arr7.append(0)
    else:
        if response['data']['totalReports'] == 0:
            print 'According to AbuseIPDB, this IP has never been reported for abuse'
            arr7.append(0)
        else:
            arr7.append(1)
            print 'According to AbuseIPDB, this IP has been reported for abuse ' + str(response['data']['totalReports']) + ' times in the past 90 days. The IP has been reported for the following reasons:'
            for i in response['data']['reports']:
                arr4.append(i['categories'])
            for i in arr4:
                if type(i) is list:
                    for k in i:
                        arr5.append(k)
                else:
                    arr5.append(i)
            arr6 = np.unique(arr5)
            f = open('abuseIPDB.yaml', 'r')
            c = yaml.safe_load(f)
            for i in arr6:
                try:
                    print "- " + c["ID"][i]
                except:
                    continue
            f.close()






def auth0(a):
    ip = a
    headers = {'accept': 'application/json', 'x-auth-token': 'YOUR_AUTH_TOKEN'}
    url = 'https://signals.api.auth0.com/v2.0/ip/' + str(ip)
    req = requests.get(url, headers=headers)
    req.text  #json
    req2 = json.loads(req.content)
    dict = req2['fullip']
    df = pd.DataFrame.from_dict(dict)
    #df.score['ip']
    print '\n' + 'IP Address in Question: ' + ip
    print 'Country: ' + str(df.geo.country)
    print '\n' + '=========================' + '\n'
    arr = ['score', 'score_180days','score_1day','score_1year','score_30days','score_7days','score_90days']
    for i in arr:
        arr2.append(df.history.loc[i] * 1)
    sumScore = np.sum(arr2)


    print '\n\n' + 'According to auth0: ',
    if sumScore == 0:
        print 'No history of maliciousness'
        arr7.append(0)
    elif 3 > sumScore > 0:
        print 'Suspicious'
        arr7.append(1)
    elif sumScore >= 3:
        print 'Malicious'
        arr7.append(2)
    print '\n'


def otxLookup(address):
    r = requests.get('https://otx.alienvault.com/api/v1/indicators/IPv4/' + str(address))
    req = json.loads(r.text)
    if len(req['pulse_info']['pulses']) > 0:
        arr7.append(1)
        print '\n\n' + 'According to Open Threat Exchange, this IP has been reported ' + str(req['pulse_info']['count']) + ' times. '
        print 'These were the names of the IOC dumps containing this IP: '
        for i in req['pulse_info']['pulses']:
            if "test".lower() not in i['name'].lower():
                print '- ' + str(i['name'])
            else:
                continue
    else:
        arr7.append(0)
        'According to Open Threat Exhange, this IP has not been reported on any Indicator of Compromise repositories.'


def emergingThreats(address):
    url = 'http://rules.emergingthreats.net/blockrules/compromised-ips.txt'
    req = requests.get(url)
    arr = req.text.split('\n')
    arr2 = []
    arr2.append(address)
    lst_arr2 = set(arr2)
    intersect = lst_arr2.intersection(arr)
    intersect_aslist = list(intersect)
    if intersect_aslist:
        print "This IP appears in the Emerging Threats Compromised IP list."
        arr7.append(1)
    else:
        print "This IP does not appear in the Emerging Threats Compromised IP list."
        arr7.append(0)




def myipms_files_blacklist(address):
    req = requests.get('https://myip.ms/files/blacklist/general/latest_blacklist.txt')
    r = req.text.split('\t\t\t')
    ipPattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    findIP = re.findall(ipPattern,req.text)
    arr2.append(address)
    lst_arr2 = set(arr2)
    intersect = lst_arr2.intersection(findIP)
    intersect_aslist = list(intersect)
    if intersect_aslist:
        print "This IP appears in the MyIP.MS Real-Time Blacklist database."
        arr7.append(1)
    else:
        print "This IP does not appear in the MyIP.MS Real-Time Blacklist database."
        arr7.append(0)



# for i in req['pulse_info']['pulses']:
#len(req['pulse_info']['pulses'])
#req['pulse_info']['count'] how many pulses





print '=========================' + '\n'
auth0(address)
print '\n' + '=========================' + '\n'
emergingThreats(address)
print '\n' + '=========================' + '\n'
myipms_files_blacklist(address)
print '\n' + '=========================' + '\n'
otxLookup(address)
print '\n' + '=========================' + '\n'
abuseIPDB(address)
print '\n' + '=========================' + '\n'


print '+++++++++++++++++++++++++' + '\n'
if np.sum(arr7) >= 4:
    print 'Overall Recommendation: Block'
elif 0 < np.sum(arr7) <= 3:
    print 'Overall Recommendation: Shun for 1 day'
elif np.sum(arr7) == 0:
    print 'Overall recommendation: Do not block'
print 'Overall score: ' + str(np.sum(arr7)) + ' out of 6 points.'
print '\n' + '+++++++++++++++++++++++++'
