from flask import Flask, render_template, request, redirect, url_for, session
from datetime import datetime
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import subprocess
import os
import json
import time
import uuid
import requests
from dotenv import load_dotenv
import xml.etree.ElementTree as ET
from flask_mail import Mail, Message
from bs4 import BeautifulSoup
app = Flask(__name__)
load_dotenv() 
  
app.secret_key = 'xyzsdfg'
  
app.config['MYSQL_HOST'] = os.getenv("HOST_NAME")
app.config['MYSQL_USER'] = os.getenv("USER_NAME")
app.config['MYSQL_PASSWORD'] = os.getenv("PASSWORD")
app.config['MYSQL_DB'] = os.getenv("DB_NAME")
app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER")
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.getenv("MAIL_NAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_SENDER")
app.config['MAIL_USE_TLS'] = False  
app.config['MAIL_USE_SSL'] = True  
MYKEY = os.getenv("ENCRYP_KEY")

mail = Mail(app)

IMAGE_FOLDER = os.path.join('static', 'image')
app.config['IMAGE_PATH'] = IMAGE_FOLDER
LOGO_PATH = os.path.join(app.config['IMAGE_PATH'], 'logo.png')
CEO_PATH = os.path.join(app.config['IMAGE_PATH'], 'ceo.png')
BG_PATH = os.path.join(app.config['IMAGE_PATH'], 'bg.png')
STEP_PATH = os.path.join(app.config['IMAGE_PATH'], 'urlstep.gif')
CAPTCHA_PATH = os.path.join(app.config['IMAGE_PATH'], 'captcha-bg.png')
targetRecord = ''
target_result = ''
target_function = ''
oneFeaturesList = ''
SQLmessage = ''
reset_token = ''
folderName = 'My Scan'
flag = 'none'
mysql = MySQL(app)
def loadFolder():
    #display all the available folder for user
    folderName= []
    jsonFolderList=''
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT FolderName FROM folder WHERE UserID = % s', (session['UserID'],))
    folderSQLData = cursor.fetchall()  
    for x in folderSQLData:
        folderName.append(x['FolderName'])
    jsonFolderList = json.dumps(folderName)
    return(jsonFolderList)

def loadFunctions(pageName,targetData):
    #display all the available scan templates
    functionSQLData = ''
    allFeaturesList = ''
    global oneFeaturesList
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM `functions` WHERE 1")
    functionSQLData = cursor.fetchall()
    extracted_data = []
   
    if(pageName == 'scan'):
        for features in functionSQLData:
            item_values = [
                features['FunctionID'],
                features['FunctionName'],
                features['Icon'],
                features['Type'],
                features['ShortDescription']
            ]
            extracted_data.append(item_values)
            allFeaturesList = json.dumps(extracted_data)
        return(allFeaturesList)
    elif (pageName == 'config'): 
        filtered_data = [item for item in functionSQLData if item['FunctionName'] == targetData]
        for features in filtered_data:
            item_values = [
                features['FunctionID'],
                features['FunctionName'],
                features['LongDescription'],
                features['Script'],
                features['URLReferences']
            ]
            extracted_data.append(item_values)
            oneFeaturesList = extracted_data
        return(extracted_data)
   
def loadScript(target, url):
    #perform different kind of scanning
    function =  oneFeaturesList[0][1]
    script = oneFeaturesList[0][3]
    result = []
    vulnerabilityDetails = []
    CriticalAmount = 0
    HighAmount = 0
    MediumAmount = 0 
    LowAmount = 0
    InfoAmount = 0
    notFound = []
    vulnerabilityList = []
    decoded_output = ""
    with open("cves\CVE2022.txt", 'r') as file:
        json2022CVEData = json.load(file)
    with open("cves\CVE2021.txt", 'r') as file:
        json2021CVEData = json.load(file)
    with open("cves\CVE2020.txt", 'r') as file:
        json2020CVEData = json.load(file)
    with open("cves\CVE2019.txt", 'r') as file:
        json2019CVEData = json.load(file)
    with open("cves\CVE2018.txt", 'r') as file:
        json2018CVEData = json.load(file)
    with open("cves\CVE2017.txt", 'r') as file:
        json2017CVEData = json.load(file)
    with open("cves\CVE2016.txt", 'r') as file:
        json2016CVEData = json.load(file)
    with open("cves\CVE2015.txt", 'r') as file:
        json2015CVEData = json.load(file)
    with open("cves\CVE2014.txt", 'r') as file:
        json2014CVEData = json.load(file)
    with open("cves\CVE2013.txt", 'r') as file:
        json2013CVEData = json.load(file)
    with open("cves\CVE2012.txt", 'r') as file:
        json2012CVEData = json.load(file)
    with open("cves\CVE2011.txt", 'r') as file:
        json2011CVEData = json.load(file)
    with open("cves\CVE2010.txt", 'r') as file:
        json2010CVEData = json.load(file)
    with open("cves\CVE2009.txt", 'r') as file:
        json2009CVEData = json.load(file)
    with open("cves\CVE2008.txt", 'r') as file:
        json2008CVEData = json.load(file)
    with open("cves\CVE2007.txt", 'r') as file:
        json2007CVEData = json.load(file)
    with open("cves\CVE2006.txt", 'r') as file:
        json2012CVEData = json.load(file)
    with open("cves\CVE2006.txt", 'r') as file:
        json2006CVEData = json.load(file)
    with open("cves\CVE2005.txt", 'r') as file:
        json2005CVEData = json.load(file)
    with open("cves\CVE2004.txt", 'r') as file:
        json2004CVEData = json.load(file)
    with open("cves\CVE2003.txt", 'r') as file:
        json2003CVEData = json.load(file)
    with open("cves\CVE2002.txt", 'r') as file:
        json2002CVEData = json.load(file)
    
    if function == "Nikto":  
        script = script.replace("WEBURL", url)
        directory = r"C:\Users\USER\Desktop\nikto\program"
        os.chdir(directory)

        completeScript = script + " " + target
        output = subprocess.run(completeScript, shell=True, capture_output=True, text=True)
        decoded_output = output.stdout
        
    else:
        if function == "Check SQL-injection" or function == "Check XXS" or function == "Check backup files":
            script = script.replace("WEBURL", url)
        completeScript = script + " " + target
        output = subprocess.check_output(completeScript, shell=True)
        decoded_output = output.decode("utf-8")
    match function:
        case "Host discovery":
            ip_pattern = re.compile(r"Nmap scan report for ([\d.]+)")
            mac_pattern = re.compile(r"MAC Address: ([\w:]+)")

            ip_addresses = re.findall(ip_pattern, decoded_output)
            mac_addresses = re.findall(mac_pattern, decoded_output)
            mac_addresses.append('Your-Mac')
            combine_data = []
            for i in range(len(ip_addresses)):
                combine_data.append({"IPAddress":ip_addresses[i],"MACAddress":mac_addresses[i]})
            host = {
                "Host":target,
                "Critical":CriticalAmount,
                "High":HighAmount,
                "Medium":MediumAmount,
                "Low":LowAmount,
                "Info":1,
                "Total":1,
                "Details":combine_data
            }
            result.append(host)

        case "Vulnerability scanning":
            cve_pattern = r"CVE-\d{4}-\d+"
            cve_codes = re.findall(cve_pattern, decoded_output)
            if cve_codes:
                vulnerabilityList = [cve for cve in cve_codes if not re.search(r"ERROR|false", cve)]
            
            smb_pattern = r"smb-vuln-(cve-\d{4}-\d+|ms\d{2}-\d{3})(?:: (true|false|ERROR))?"
            smb_vulns = re.findall(smb_pattern, decoded_output)

            if smb_vulns:
                for smb_vuln in smb_vulns:
                    vuln_id, is_vulnerable = smb_vuln
                    if is_vulnerable != "ERROR" and is_vulnerable != "false":
                        full_id = f"smb-vuln-{vuln_id}"
                        vulnerabilityList.append(full_id)
            uniquevulnerabilityList = list(set(vulnerabilityList))
            for target_cve in uniquevulnerabilityList:
                found = False  
                years = re.findall(r"CVE-(\d{4})", target_cve)
               
                match years[0]:
                    case "2022":
                        CVEFolder = json2022CVEData
                    case "2021":
                       CVEFolder = json2021CVEData
                    case "2020":
                        CVEFolder = json2020CVEData
                    case "2019":
                       CVEFolder = json2019CVEData
                    case "2018":
                        CVEFolder = json2018CVEData
                    case "2017":
                       CVEFolder = json2017CVEData
                    case "2016":
                        CVEFolder = json2016CVEData
                    case "2015":
                        CVEFolder = json2015CVEData
                    case "2014":
                       CVEFolder = json2014CVEData
                    case "2013":
                        CVEFolder = json2013CVEData
                    case "2012":
                       CVEFolder = json2012CVEData
                    case "2011":
                        CVEFolder = json2011CVEData
                    case "2010":
                       CVEFolder = json2010CVEData
                    case "2009":
                        CVEFolder = json2009CVEData
                    case "2008":
                        CVEFolder = json2008CVEData
                    case "2007":
                       CVEFolder = json2007CVEData
                    case "2006":
                        CVEFolder = json2006CVEData
                    case "2005":
                       CVEFolder = json2005CVEData
                    case "2004":
                        CVEFolder = json2004CVEData
                    case "2003":
                       CVEFolder = json2003CVEData
                    case "2002":
                        CVEFolder = json2002CVEData
                for item in CVEFolder:
                    if item.get('cve', {}).get('CVE_data_meta', {}).get('ID') == target_cve:
                        found = True
                        cveID = item['cve']['CVE_data_meta']['ID']
                        references = item['cve']['references']['reference_data']
                        description = item['cve']['description']['description_data'][0]['value']
                        baseScore = item['impact']['baseMetricV3']['cvssV3']['baseScore']
                        baseSeverity = item['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                        publishedDate = item['publishedDate']
                        lastModifiedDate = item['lastModifiedDate']
                        break

                if found:
                    description = description.replace('"', '')
                    description = description.replace("'", 'L2G ')
                    description = description.replace("\\", 'L3G ')
                    if baseSeverity == "CRITICAL":
                        CriticalAmount +=1
                    elif baseSeverity == "HIGH":
                        HighAmount +=1
                    elif baseSeverity == "MEDIUM":
                        MediumAmount +=1
                    elif baseSeverity == "LOW":
                        LowAmount +=1
                    urlList =[]
                    for ref in references:
                        urlList.append( ref['url'])
                    vulnerabilityDetails.append({"CVE ID":cveID,"Description":description,"Base Score":baseScore,"Base Severity":baseSeverity,"Published Date":publishedDate,"Last Modified Date":lastModifiedDate,"References":urlList})
                else:
                    notFound.append(target_cve)
           
            host = {
                    "Host":target,
                    "Critical":CriticalAmount,
                    "High":HighAmount,
                    "Medium":MediumAmount,
                    "Low":LowAmount,
                    "Info":0,
                    "Total":CriticalAmount + HighAmount + MediumAmount + LowAmount,
                    "Details":vulnerabilityDetails
                }
            result.append(host)

        case "Check WannaCry":
            if "VULNERABLE" in decoded_output:
                found = False
                for item in json2017CVEData:
                    if item.get('cve', {}).get('CVE_data_meta', {}).get('ID') == "CVE-2017-0144":
                        cveID = item['cve']['CVE_data_meta']['ID']
                        references = item['cve']['references']['reference_data']
                        description = item['cve']['description']['description_data'][0]['value']
                        baseScore = item['impact']['baseMetricV3']['cvssV3']['baseScore']
                        baseSeverity = item['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                        publishedDate = item['publishedDate']
                        lastModifiedDate = item['lastModifiedDate']
                        found = True
                        break

                if found:
                    description = description.replace('"', '')
                    description = description.replace("'", 'L2G ')
                    description = description.replace("\\", 'L3G ')
                    if baseSeverity == "CRITICAL":
                        CriticalAmount +=1
                    elif baseSeverity == "HIGH":
                        HighAmount +=1
                    elif baseSeverity == "MEDIUM":
                        MediumAmount +=1
                    elif baseSeverity == "LOW":
                        LowAmount +=1
                    urlList =[]
                    for ref in references:
                        urlList.append( ref['url'])
                    vulnerabilityDetails.append({"CVE ID":cveID,"Description":description,"Base Score":baseScore,"Base Severity":baseSeverity,"Published Date":publishedDate,"Last Modified Date":lastModifiedDate,"References":urlList})
                host = {
                    "Host":target,
                    "Critical":CriticalAmount,
                    "High":HighAmount,
                    "Medium":MediumAmount,
                    "Low":LowAmount,
                    "Info":0,
                    "Total":CriticalAmount + HighAmount + MediumAmount + LowAmount,
                    "Details":vulnerabilityDetails
                }
                result.append(host)
            else:
                host = {
                        "Host":target,
                        "Critical":CriticalAmount,
                        "High":HighAmount,
                        "Medium":MediumAmount,
                        "Low":LowAmount,
                        "Info":1,
                        "Total":1,
                        "Details":"No vulnerability found."
                    }
                result.append(host)

        case "Dynamic scan":  
            lines = decoded_output.strip().split('\n')
            port_lines = lines[5:-3] 

            ports = []
            services = []
            for line in port_lines:
                values = line.split()
                if len(values) >= 3:
                    port = values[0].split('/')[0]
                    service = values[2]
                    ports.append(port)
                    services.append(service)

            for i in range(len(ports)):
                vulnerabilityDetails.append(dict({'Port': ports[i], 'Service': services[i]}))

            host = {
                    "Host":target,
                    "Critical":CriticalAmount,
                    "High":HighAmount,
                    "Medium":MediumAmount,
                    "Low":LowAmount,
                    "Info":3,
                    "Total":3,
                    "Details":vulnerabilityDetails
                }
            result.append(host)

        case "Check SMTP vulnerability":  
            vulnerabilities = re.findall(r"(smtp-vuln-cve\d{4}-\d{1,4})", decoded_output)
            uniquevulnerability = list(set(vulnerabilities))
            vulnerabilityCode = [vuln.replace("smtp-vuln-", "") for vuln in uniquevulnerability]
            vulnerabilityList = [vuln.replace("cve", "CVE-") for vuln in vulnerabilityCode]
            CVEFolder = ""
            for target_cve in vulnerabilityList:
                found = False  
                years = re.findall(r"CVE-(\d{4})", target_cve)
                match years[0]:
                    case "2022":
                        CVEFolder = json2022CVEData
                    case "2021":
                        CVEFolder = json2021CVEData
                    case "2020":
                        CVEFolder = json2020CVEData
                    case "2019":
                        CVEFolder = json2019CVEData
                    case "2018":
                        CVEFolder = json2018CVEData
                    case "2017":
                        CVEFolder = json2017CVEData
                    case "2016":
                        CVEFolder = json2016CVEData
                    case "2015":
                        CVEFolder = json2015CVEData
                    case "2014":
                        CVEFolder = json2014CVEData
                    case "2013":
                        CVEFolder = json2013CVEData
                    case "2012":
                        CVEFolder = json2012CVEData
                    case "2011":
                        CVEFolder = json2011CVEData
                    case "2010":
                        CVEFolder = json2010CVEData
                    case "2009":
                        CVEFolder = json2009CVEData
                    case "2008":
                        CVEFolder = json2008CVEData
                    case "2007":
                        CVEFolder = json2007CVEData
                    case "2006":
                        CVEFolder = json2006CVEData
                    case "2005":
                        CVEFolder = json2005CVEData
                    case "2004":
                        CVEFolder = json2004CVEData
                    case "2003":
                        CVEFolder = json2003CVEData
                    case "2002":
                        CVEFolder = json2002CVEData
                for item in CVEFolder:
                    if item.get('cve', {}).get('CVE_data_meta', {}).get('ID') == target_cve:
                        found = True
                        cveID = item['cve']['CVE_data_meta']['ID']
                        references = item['cve']['references']['reference_data']
                        description = item['cve']['description']['description_data'][0]['value']
                        baseScore = item['impact']['baseMetricV3']['cvssV3']['baseScore']
                        baseSeverity = item['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                        publishedDate = item['publishedDate']
                        lastModifiedDate = item['lastModifiedDate']
                        break
                if found:
                    description = description.replace('"', '')
                    description = description.replace("'", 'L2G ')
                    description = description.replace("\\", 'L3G ')
                    if baseSeverity == "CRITICAL":
                        CriticalAmount +=1
                    elif baseSeverity == "HIGH":
                        HighAmount +=1
                    elif baseSeverity == "MEDIUM":
                        MediumAmount +=1
                    elif baseSeverity == "LOW":
                        LowAmount +=1
                    urlList =[]
                    for ref in references:
                        urlList.append( ref['url'])
                    vulnerabilityDetails.append({"CVE ID":cveID,"Description":description,"Base Score":baseScore,"Base Severity":baseSeverity,
                                                 "Published Date":publishedDate,"Last Modified Date":lastModifiedDate,"References":urlList})
                else:
                    notFound.append(target_cve)

            host = {
                    "Host":target,
                    "Critical":CriticalAmount,
                    "High":HighAmount,
                    "Medium":MediumAmount,
                    "Low":LowAmount,
                    "Info":0,
                    "Total":CriticalAmount + HighAmount + MediumAmount + LowAmount,
                    "Details":vulnerabilityDetails

                }
            result.append(host)
        case "Check WebApp Vulnerability":
            vulnerabilityList = "" 
            cve_pattern = r"CVE-\d{4}-\d+"
            cve_codes = re.findall(cve_pattern, decoded_output)
            if cve_codes:
                vulnerabilityList = [cve for cve in cve_codes if not re.search(r"ERROR|false", cve)]
            
            smb_pattern = r"smb-vuln-(cve-\d{4}-\d+|ms\d{2}-\d{3})(?:: (true|false|ERROR))?"
            smb_vulns = re.findall(smb_pattern, decoded_output)

            if smb_vulns:
                for smb_vuln in smb_vulns:
                    vuln_id, is_vulnerable = smb_vuln
                    if is_vulnerable != "ERROR" and is_vulnerable != "false":
                        full_id = f"smb-vuln-{vuln_id}"
                        vulnerabilityList.append(full_id)
            uniquevulnerabilityList = list(set(vulnerabilityList))
            for target_cve in uniquevulnerabilityList:
                found = False  
                years = re.findall(r"CVE-(\d{4})", target_cve)
                
                match years[0]:
                    case "2022":
                        CVEFolder = json2022CVEData
                    case "2021":
                        CVEFolder = json2021CVEData
                    case "2020":
                        CVEFolder = json2020CVEData
                    case "2019":
                        CVEFolder = json2019CVEData
                    case "2018":
                        CVEFolder = json2018CVEData
                    case "2017":
                        CVEFolder = json2017CVEData
                    case "2016":
                        CVEFolder = json2016CVEData
                    case "2015":
                        CVEFolder = json2015CVEData
                    case "2014":
                        CVEFolder = json2014CVEData
                    case "2013":
                        CVEFolder = json2013CVEData
                    case "2012":
                        CVEFolder = json2012CVEData
                    case "2011":
                        CVEFolder = json2011CVEData
                    case "2010":
                        CVEFolder = json2010CVEData
                    case "2009":
                        CVEFolder = json2009CVEData
                    case "2008":
                        CVEFolder = json2008CVEData
                    case "2007":
                        CVEFolder = json2007CVEData
                    case "2006":
                        CVEFolder = json2006CVEData
                    case "2005":
                        CVEFolder = json2005CVEData
                    case "2004":
                        CVEFolder = json2004CVEData
                    case "2003":
                        CVEFolder = json2003CVEData
                    case "2002":
                        CVEFolder = json2002CVEData
                for item in CVEFolder:
                    if item.get('cve', {}).get('CVE_data_meta', {}).get('ID') == target_cve:
                        found = True
                        cveID = item['cve']['CVE_data_meta']['ID']
                        references = item['cve']['references']['reference_data']
                        description = item['cve']['description']['description_data'][0]['value']
                        baseScore = item['impact']['baseMetricV3']['cvssV3']['baseScore']
                        baseSeverity = item['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                        publishedDate = item['publishedDate']
                        lastModifiedDate = item['lastModifiedDate']
                        break

                if found:
                    description = description.replace('"', '')
                    description = description.replace("'", 'L2G ')
                    description = description.replace("\\", 'L3G ')
                    if baseSeverity == "CRITICAL":
                        CriticalAmount +=1
                    elif baseSeverity == "HIGH":
                        HighAmount +=1
                    elif baseSeverity == "MEDIUM":
                        MediumAmount +=1
                    elif baseSeverity == "LOW":
                        LowAmount +=1
                    urlList =[]
                    for ref in references:
                        urlList.append( ref['url'])
                    vulnerabilityDetails.append({"CVE ID":cveID,"Description":description,"Base Score":baseScore,"Base Severity":baseSeverity,"Published Date":publishedDate,"Last Modified Date":lastModifiedDate,"References":urlList})
            
            if len(vulnerabilityDetails) == 0:
                host = {
                    "Host":target,
                    "Critical":0,
                    "High":0,
                    "Medium":0,
                    "Low":0,
                    "Info":1,
                    "Total":1,
                    "Details":'No Vulnerability found'
                }
            else:
                host = {
                    "Host":"target",
                    "Critical":CriticalAmount,
                    "High":HighAmount,
                    "Medium":MediumAmount,
                    "Low":LowAmount,
                    "Info":0,
                    "Total":CriticalAmount + HighAmount + MediumAmount + LowAmount + InfoAmount,
                    "Details":vulnerabilityDetails
                }
            result.append(host)
        case "Check stuxnet":  
            if "Likely infected with Stuxnet" in decoded_output:
                for item in json2010CVEData:
                    if item.get('cve', {}).get('CVE_data_meta', {}).get('ID') == "CVE-2010-2568":
                        found = True
                        cveID = item['cve']['CVE_data_meta']['ID']
                        references = item['cve']['references']['reference_data']
                        description = item['cve']['description']['description_data'][0]['value']
                        baseScore = item['impact']['baseMetricV3']['cvssV3']['baseScore']
                        baseSeverity = item['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                        publishedDate = item['publishedDate']
                        lastModifiedDate = item['lastModifiedDate']
                        break
                if found:
                    description = description.replace('"', '')
                    description = description.replace("'", 'L2G ')
                    description = description.replace("\\", 'L3G ')
                    if baseSeverity == "CRITICAL":
                        CriticalAmount +=1
                    elif baseSeverity == "HIGH":
                        HighAmount +=1
                    elif baseSeverity == "MEDIUM":
                        MediumAmount +=1
                    elif baseSeverity == "LOW":
                        LowAmount +=1
                    urlList =[]
                    for ref in references:
                        urlList.append( ref['url'])
                    vulnerabilityDetails.append({"CVE ID":cveID,"Description":description,"Base Score":baseScore,"Base Severity":baseSeverity,"Published Date":publishedDate,"Last Modified Date":lastModifiedDate,"References":urlList})

                host = {
                        "Host":target,
                        "Critical":CriticalAmount,
                        "High":HighAmount,
                        "Medium":MediumAmount,
                        "Low":LowAmount,
                        "Info":0,
                        "Total":CriticalAmount + HighAmount + MediumAmount + LowAmount,
                        "Details":vulnerabilityDetails
                    }
                result.append(host)
            else:
                host = {
                        "Host":target,
                        "Critical":CriticalAmount,
                        "High":HighAmount,
                        "Medium":MediumAmount,
                        "Low":LowAmount,
                        "Info":1,
                        "Total":1,
                        "Details":"No vulnerability found."
                    }
                result.append(host)

        case "Check share file":  
            pattern = r"\| smb-enum-shares:\n\|   Sharename\s+Type\s+Comment\n\|   ---------\s+----\s+-------\n(.*?)(?=\n\w|\n$)"
            matches = re.search(pattern, decoded_output, re.DOTALL)

            if matches:
                shares_info = matches.group(1)
                host = {
                        "Host":target,
                        "Critical":CriticalAmount,
                        "High":HighAmount,
                        "Medium":MediumAmount,
                        "Low":LowAmount,
                        "Info":1,
                        "Total":CriticalAmount + HighAmount + MediumAmount + LowAmount,
                        "Details": shares_info
                    }
                result.append(host)
            else:
                host = {
                        "Host":target,
                        "Critical":CriticalAmount,
                        "High":HighAmount,
                        "Medium":MediumAmount,
                        "Low":LowAmount,
                        "Info":1,
                        "Total":1,
                        "Details": "No sharing any file."
                    }
                result.append(host)

        case "Check SMB vulnerability":  
                pattern = r"IDs:\s+(CVE:[A-Za-z0-9\-]+)"
                vulnerabilityList = re.findall(pattern, decoded_output)
                modifiedVulnerabilityList = [element.replace('CVE:', '') for element in vulnerabilityList]
                for target_cve in modifiedVulnerabilityList:
                    target_cve.replace('CVE:', '')
                    found = False  
                    years = re.findall(r"CVE-(\d{4})", target_cve)

                    match years[0]:
                        case "2022":
                            CVEFolder = json2022CVEData
                        case "2021":
                            CVEFolder = json2021CVEData
                        case "2020":
                            CVEFolder = json2020CVEData
                        case "2019":
                            CVEFolder = json2019CVEData
                        case "2018":
                            CVEFolder = json2018CVEData
                        case "2017":
                            CVEFolder = json2017CVEData
                        case "2016":
                            CVEFolder = json2016CVEData
                        case "2015":
                            CVEFolder = json2015CVEData
                        case "2014":
                            CVEFolder = json2014CVEData
                        case "2013":
                            CVEFolder = json2013CVEData
                        case "2012":
                            CVEFolder = json2012CVEData
                        case "2011":
                            CVEFolder = json2011CVEData
                        case "2010":
                            CVEFolder = json2010CVEData
                        case "2009":
                            CVEFolder = json2009CVEData
                        case "2008":
                            CVEFolder = json2008CVEData
                        case "2007":
                            CVEFolder = json2007CVEData
                        case "2006":
                            CVEFolder = json2006CVEData
                        case "2005":
                            CVEFolder = json2005CVEData
                        case "2004":
                            CVEFolder = json2004CVEData
                        case "2003":
                            CVEFolder = json2003CVEData
                        case "2002":
                            CVEFolder = json2002CVEData
                    for item in CVEFolder:
                        if item.get('cve', {}).get('CVE_data_meta', {}).get('ID') == target_cve:
                            found = True
                            cveID = item['cve']['CVE_data_meta']['ID']  
                            references = item['cve']['references']['reference_data']
                            description = item['cve']['description']['description_data'][0]['value']
                            baseScore = item['impact']['baseMetricV3']['cvssV3']['baseScore']
                            baseSeverity = item['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                            publishedDate = item['publishedDate']
                            lastModifiedDate = item['lastModifiedDate']
                            break
                    if found:
                        description = description.replace('"', '')
                        description = description.replace("'", 'L2G ')
                        description = description.replace("\\", 'L3G ')
                        if baseSeverity == "CRITICAL":
                            CriticalAmount +=1
                        elif baseSeverity == "HIGH":
                            HighAmount +=1
                        elif baseSeverity == "MEDIUM":
                            MediumAmount +=1
                        elif baseSeverity == "LOW":
                            LowAmount +=1
                        urlList =[]
                        for ref in references:
                            urlList.append( ref['url'])
                        vulnerabilityDetails.append({"CVE ID":cveID,"Description":description,"Base Score":baseScore,"Base Severity":baseSeverity,"Published Date":publishedDate,"Last Modified Date":lastModifiedDate,"References":urlList})
                    else:
                        notFound.append(target_cve)
                if CriticalAmount + HighAmount + MediumAmount + LowAmount == 0:
                    host = {
                            "Host":target,
                            "Critical":CriticalAmount,
                            "High":HighAmount,
                            "Medium":MediumAmount,
                            "Low":LowAmount,
                            "Info":1,
                            "Total":1,
                            "Details":vulnerabilityDetails

                        }
                else:
                    host = {
                        "Host":target,
                        "Critical":CriticalAmount,
                        "High":HighAmount,
                        "Medium":MediumAmount,
                        "Low":LowAmount,
                        "Info":0,
                        "Total":CriticalAmount + HighAmount + MediumAmount + LowAmount,
                        "Details":vulnerabilityDetails

                    }
                result.append(host)
        
        case "Information Disclosure":
            port_states = re.findall(r'\d+/tcp\s+([^\n]+)\s+([^\n]+)', decoded_output)
            Details = []
            Data = {}
            for port, state in port_states:
                port_match = re.search(rf'{port}.*?Server: (.*?)\n.*?Last-Modified: (.*?)\n.*?ETag: (.*?)\n.*?http-title: (.*?)\n.*?Requested resource was (.*?)\n', decoded_output, re.DOTALL)
                if port_match:
                    server = port_match.group(1)
                    server = server.replace('\r', '')
                    last_modified = port_match.group(2)
                    etag = port_match.group(3)
                    etag = etag.replace('"', '')
                    http_title = port_match.group(4)
                    requested_resource = port_match.group(5)
                    Data[port] = {
                        "Service": state.strip(),
                        "Server": server.strip(),
                        "Last-Modified": last_modified.strip(),
                        "ETag": etag.strip(),
                        "http-title": http_title.strip(),
                        "Requested resource": requested_resource.strip()
                    }
                else:
                    Data[port] = {
                        "Service": state.strip(),
                        "Server": "Not found",
                        "Last-Modified": "Not found",
                        "ETag": "Not found",
                        "http-title": "Not found",
                        "Requested resource": "Not found"
                    }

            for port, data in Data.items():
                port = port.replace('\r', '')
                Details.append({
                    "Port":port,
                    "State": data["Service"],
                    "Server": data["Server"],
                    "Last-Modified": data["Last-Modified"],
                    "ETag": data["ETag"],
                    "http-title": data["http-title"],
                    "Requested resource": data["Requested resource"]
                })
            host = {
                "Host":target,
                "Critical":CriticalAmount,
                "High":HighAmount,
                "Medium":MediumAmount,
                "Low":LowAmount,
                "Info":1,
                "Total":1,
                "Details": Details
            }
            result.append(host)

        case "Check backup files":  
            port_pattern = r'(\d+)/tcp\s+(\w+)\s+(\w+)'
            detail_pattern = r'\|(.*)'

            matches = re.findall(port_pattern, decoded_output)
            combine_details = []
            for match in matches:
                port, state, service = match
                details = []

                detail_matches = re.findall(detail_pattern, decoded_output)
                details.extend(detail_matches)
                combine_details.append({"PORT": port, "STATE": state, "SERVICE": service, "DETAILS": details})

            host = {
                "Host":target,
                "Critical":CriticalAmount,
                "High":HighAmount,
                "Medium":MediumAmount,
                "Low":LowAmount,
                "Info":1,
                "Total":1,
                "Details": combine_details
            }
            result.append(host)

        case "Check hosting websites":
            port_info = re.findall(r'(\d+/tcp)\s+(\w+)\s+(\w+)\s*(.*)', decoded_output)
            details = re.findall(r'\|\s*(.*?)$', decoded_output, re.MULTILINE)
            Data = []
            UrlArray = []
            host="asd"
            for port, state, service, version in port_info:
                if state == 'closed':
                    break
                else:
                    Data.append({
                        "PORT": port,
                        "STATE": state,
                        "SERVICE": service,
                        "DETAILS": [version] + details
                    })

            if len(Data) == 0:
                host = {
                    "Host":target,
                    "Critical":CriticalAmount,
                    "High":HighAmount,
                    "Medium":MediumAmount,
                    "Low":LowAmount,
                    "Info":1,
                    "Total":1,
                    "Details": {"The device is not hosting any website"}
                }
            else:
                for item in Data:   
                    details = item['DETAILS']
                    item['DETAILS'] = [d.replace('\r', '') for d in details]
                    UrlArray.append(item['DETAILS'])

                host = {
                    "Host":target,
                    "Critical":CriticalAmount,
                    "High":HighAmount,
                    "Medium":MediumAmount,
                    "Low":LowAmount,
                    "Info":2,
                    "Total":2,
                    "Details": UrlArray
                }
            result.append(host)

        case "Check all files":  
            port_info = re.findall(r'(\d+/tcp)\s+(\w+)\s+(\w+)\s*(.*)', decoded_output)
            details = re.findall(r'\|\s*(.*?)$', decoded_output, re.MULTILINE)
            Data = []
            
            for port, state, service, version in port_info:
                Data.append({
                    "PORT": port,
                    "STATE": state,
                    "SERVICE": service,
                    "DETAILS": [version] + details
                })
            for item in Data:
                details = item['DETAILS']
                item['DETAILS'] = [d.replace('\r', '') for d in details]
            host = {
                    "Host":target,
                    "Critical":CriticalAmount,
                    "High":HighAmount,
                    "Medium":MediumAmount,
                    "Low":LowAmount,
                    "Info":1,
                    "Total":1,
                    "Details": Data
                }
            result.append(host)

        case "Check XXS":
            vulnerabilities = []
            lines = decoded_output.split("\n")
            for i, line in enumerate(lines):
                if "vulnerability found!" in line or "Unsafe output escaping found!" in line:
                    record = {}
                    record["Description"] = lines[i + 1].lstrip("Description: ")
                    record["Impact"] = lines[i + 2].lstrip("Impact: ")
                    record["Solution"] = lines[i + 3].lstrip("Solution: ")
                    vulnerabilities.append(record)

            json_data = json.dumps(vulnerabilities, indent=4)
            if len(vulnerabilities) == 0 :
                host = {
                    "Host":target,
                    "Critical":CriticalAmount,
                    "High":HighAmount,
                    "Medium":MediumAmount,
                    "Low":LowAmount,
                    "Info":1,
                    "Total":1,
                    "Details": "No Vulnerability found"
                }
            else:
                host = {
                    "Host":target,
                    "Critical":CriticalAmount,
                    "High":HighAmount,
                    "Medium":MediumAmount,
                    "Low":LowAmount,
                    "Info":length,
                    "Total":length,
                    "Details": json_data
                }
            result.append(host)
        case "Check SQL-injection":
            urls = re.findall(r"http[s]?://[^\s]+", decoded_output)
            urls.pop(0)
            length = len(urls)
            if length == 0:
                host = {
                    "Host":target,
                    "Critical":CriticalAmount,
                    "High":HighAmount,
                    "Medium":MediumAmount,
                    "Low":LowAmount,
                    "Info":1,
                    "Total":1,
                    "Details": 'No Vulnerability found'
                }
            else:
                host = {
                    "Host":target,
                    "Critical":CriticalAmount,
                    "High":HighAmount,
                    "Medium":MediumAmount,
                    "Low":LowAmount,
                    "Info":length,
                    "Total":length,
                    "Details": urls
                }
            result.append(host)
        case "Nikto":  
            xml_declaration_start = decoded_output.find('<?xml')
            xml_content = decoded_output[xml_declaration_start:]
            xml_validcontent = re.sub(r'\*{5,}\n[\s\S]*', '', xml_content)
            root = ET.fromstring(xml_validcontent)
            NiktoResult = []
            for item in root.findall('.//item'):
                description = item.find('description').text.replace('\n', '')
                description = description.replace('"', '')
                description = description.replace("'", 'L2G ')
                description = description.replace("\\", 'L3G ')
                url = item.find('namelink').text.replace('\n', '')
                url = url.replace('"', '')
                url = url.replace("'", 'L2G ')
                url = url.replace("\\", 'L3G ')

                data = {'Description': description, 'url': url}

                NiktoResult.append(data)   
            host = {
                    "Host":target,
                    "Critical":CriticalAmount,
                    "High":HighAmount,
                    "Medium":MediumAmount,
                    "Low":LowAmount,
                    "Info":0,
                    "Total":0,
                    "Details": NiktoResult
                }
            result.append(host)

    return(result,decoded_output,function)

@app.route('/')
@app.route('/login', methods =['GET', 'POST'])
def loginpage():
    #for user to login account
    global SQLmessage
    SQLmessage = ''
    if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
        inputEmail = request.form['email']
        inputPassword = request.form['password']
        encrypt_password = xor_encrypt(inputPassword, MYKEY)
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT UserID FROM users WHERE Email = % s AND Password = % s', (inputEmail, encrypt_password, ))
        SQLData = cursor.fetchone()
        if SQLData:
            session['loggedin'] = True
            session['UserID'] = SQLData['UserID']
            SQLmessage = ''
            return redirect(url_for('homepage'))
        else:
            SQLmessage = 'Please enter correct email / password !'
    return render_template('login.html', message = SQLmessage, logo_image=LOGO_PATH, captcha_image = CAPTCHA_PATH)
  
@app.route('/logout')
def logout():
    #for user to logout account
    session.pop('loggedin')
    session.pop('UserID')
    SQLmessage = ''
    return redirect(url_for('loginpage'))
  
@app.route('/register', methods =['GET', 'POST'])
def registerpage():
    #for user to register new account
    global SQLmessage
    if request.method == 'POST' and 'name' in request.form and 'password' in request.form and 'email' in request.form :
        userName = request.form['name']
        password = request.form['password']
        email = request.form['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT UserID FROM users WHERE Email = % s', (email, ))
        SQLData = cursor.fetchone()
        if SQLData:
            SQLmessage = 'This email been registered !'
        else:
            encryp_password = xor_encrypt(password,MYKEY)
            query = ('INSERT INTO `users`( `UserName`, `Email`, `Password`) VALUES (%s,%s,%s)')
            values = (userName, email, encryp_password, )
            cursor.execute(query, values)
            mysql.connection.commit()
            SQLmessage = ''
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT UserID FROM users WHERE Email = % s', (email, ))
            SQLData = cursor.fetchone()
            session['loggedin'] = True
            session['UserID'] = SQLData['UserID']
            insert_query = "INSERT INTO `folder`(`FolderName`, `UserID`) VALUES (%s,%s);"
            values = [("My Scan", session['UserID']), ("All", session['UserID']), ("Trash", session['UserID'])]
            for value in values:
                cursor.execute(insert_query, value)
                mysql.connection.commit()

            return redirect(url_for('homepage'))
    return render_template('register.html', message = SQLmessage, logo_image=LOGO_PATH)

@app.route('/resetpassword', methods =['GET', 'POST'])
def resetpasswordpage():
    global SQLmessage
    if 'resetpassword_email' in session and 'validtoken' in session:
        #for user to provide new password for reset password request
        if request.method == 'POST' and 'new_password' in request.form:
            inputNewPassword = request.form['new_password']
            Encrypt_password = xor_encrypt(inputNewPassword, MYKEY)
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            query = 'UPDATE `users` SET `Password`= %s WHERE Email = %s'
            values = (Encrypt_password, session['resetpassword_email'])
            cursor.execute(query, values)
            mysql.connection.commit()
            session.pop('resetpassword_email')
            session.pop('validtoken')
            SQLmessage = ''
            return redirect(url_for('loginpage'))
    else:
        return redirect(url_for('loginpage'))
    return render_template('resetpassword.html', message = SQLmessage, logo_image=LOGO_PATH)
  

@app.route('/forgetpassword', methods =['GET', 'POST'])
def forgetpasswordpage():
    global SQLmessage

    if request.method == 'POST' and 'email' in request.form:
        #for user to make reset passdword request
        inputEmail = request.form['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT UserID FROM users WHERE Email = % s', (inputEmail, ))
        SQLData = cursor.fetchone()
        if SQLData:
            generate_token()
            msg = Message('Aetherix: Password Reset', recipients=[inputEmail])
            msg.body = f'This is your token to reset password: {reset_token}. If you does not require, kindly ignore this message.'
            mail.send(msg)
            SQLmessage = ''
            session['resetpassword_email'] = inputEmail
            return redirect(url_for('validtokenpage'))
        else:
            SQLmessage = 'Email address is not available!'
  
    return render_template('forgetpassword.html', message = SQLmessage, logo_image=LOGO_PATH)
  
@app.route('/validtoken', methods =['GET', 'POST'])
def validtokenpage():

    if 'resetpassword_email' in session:
        #valid the token for reset password
        SQLmessage = ''
        if request.method == 'POST' and 'token' in request.form:
            
            inputToken = request.form['token']
            if inputToken == reset_token:
                session['validtoken'] = True
                return redirect(url_for('resetpasswordpage'))
            else:
                SQLmessage = 'Invalid token'

    else:
        return redirect(url_for('loginpage'))
    return render_template('validtoken.html', message = SQLmessage, logo_image=LOGO_PATH)

@app.route('/home', methods =['GET', 'POST'])
def homepage():
    if 'loggedin' in session:
        jsonFolderList = loadFolder()
        recorName= []  
        foldermessage = ''
        jsonRecordList=''
        global folderName 
        global flag
        global targetRecord

        #Execute the scanning
        if request.method == 'POST' and 'name' in request.form and 'target' in request.form:
            recordName = request.form['name']
            recordTarget = request.form['target']
            recorddescription = request.form['description']
            recordURL = request.form['url']
            scriptResult = loadScript(recordTarget, recordURL)
            strFormResult = str(scriptResult[0])
            current_datetime = datetime.now()
            formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            query = "INSERT INTO `record`(`RecordName`, `RecordDescription`, `Target` ,`Function`,`Result`,`OriginalReport`,`TimeDate`, `Folder`, `UserID`) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            values = (recordName,recorddescription,recordTarget,scriptResult[2],strFormResult,scriptResult[1],formatted_datetime,folderName, session['UserID'])
            cursor.execute(query, values)
            mysql.connection.commit()

        if flag == 'none' :
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT RecordID,RecordName,TimeDate FROM record WHERE folder = % s AND UserID = %s', (folderName,session['UserID'],) )
            SQLData = cursor.fetchall()
            recorName = [list(item.values()) for item in SQLData]
            jsonRecordList = json.dumps(recorName) 
            flag = 'executed'
        
        #Display all record in selected folder
        if request.method == 'POST' and 'foldername' in request.form :
            folderName = request.form['foldername']
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            if(folderName == 'All'):
                cursor.execute('SELECT RecordID,RecordName,TimeDate FROM record WHERE Folder != %s AND UserID = %s', ('Trash',session['UserID'],) )
            else:
                cursor.execute('SELECT RecordID,RecordName,TimeDate FROM record WHERE folder = % s AND UserID = %s', (folderName,session['UserID'],) )
            SQLData = cursor.fetchall()
            recorName = [list(item.values()) for item in SQLData]
            jsonRecordList = json.dumps(recorName) 
        
        #Delete record
        if request.method == 'POST' and 'targetRecord' in request.form or request.method == 'POST' and 'targetData' in request.form :
            targetRecord = request.form['targetRecord']
            targetData = request.form['targetData']
            if targetData != 'Cancelled' and targetData :
                splitData = targetData.split("|")
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                folderName = splitData[2]
                if(splitData[2] == 'Trash'):
                    query = 'DELETE FROM `record` WHERE RecordID = %s AND UserID = %s'
                    values = (splitData[0],  session['UserID'])
                    cursor.execute(query, values)
                    mysql.connection.commit()
                else:
                    query = 'UPDATE `record` SET `Folder`= %s WHERE RecordID = %s AND UserID = %s'
                    values = ('Trash',splitData[0], session['UserID'])
                    cursor.execute(query, values)
                    mysql.connection.commit()
            elif targetData == 'Cancelled':
                pass
            else: 
                #for user to view record
                return redirect(url_for('viewrecordpage'))
            
        #for user to create new folder
        if request.method == 'POST' and 'folder' in request.form:
            Inputfolder = request.form['folder']
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT FolderName FROM folder WHERE FolderName = %s AND UserID = %s', (Inputfolder,session['UserID'],) )
            SQLData = cursor.fetchall()
            if SQLData:
                foldermessage = 'Folder name taken'
            else:
                query = "INSERT INTO `folder`(`FolderName`, `UserID`) VALUES (%s,%s)"
                values = (Inputfolder, session['UserID'])
                cursor.execute(query, values)
                mysql.connection.commit()
                jsonFolderList = loadFolder()

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        if(folderName == 'All'):
            cursor.execute('SELECT RecordID,RecordName,TimeDate FROM record WHERE Folder != %s AND UserID = %s', ('Trash',session['UserID'],) )
        else:
            cursor.execute('SELECT RecordID,RecordName,TimeDate FROM record WHERE Folder = % s AND UserID = %s', (folderName,session['UserID'],) )
        SQLData = cursor.fetchall()
        recorName = [list(item.values()) for item in SQLData]
        jsonRecordList = json.dumps(recorName) 
    else:
        return redirect(url_for('loginpage'))

    return render_template('home.html',logo_image = LOGO_PATH,folderArray = jsonFolderList, recordArray = jsonRecordList, pointerFolder= folderName, previousPath= "< Back to Scan Record" , folderMessage = foldermessage)

@app.route('/scan', methods =['GET', 'POST'])
def scanpage():
    if 'loggedin' in session:
        #for user to select any available scan template
        jsonFolderList = loadFolder()
        FeaturesList = loadFunctions("scan","")
    else:
        return redirect(url_for('loginpage'))
    return render_template('scan.html',logo_image = LOGO_PATH, folderArray = jsonFolderList, pointerFolder= folderName, previousPath = "< Back to Scan Records", featuresArray = FeaturesList)

@app.route('/configure', methods =['GET', 'POST'])
def configurepage():
    if 'loggedin' in session:
        #for user to configure the scan
        jsonFolderList = loadFolder()
        jsonFeaturesList = ''
        functionNameData = ""
        if request.method == 'POST' and 'targetFunction' in request.form :
            targetFunction = request.form['targetFunction']
            splitData = targetFunction.split("|")
            functionNameData = splitData[1]
            jsonFeaturesList = loadFunctions("config",splitData[1])
        if functionNameData == '':
            return redirect(url_for('scanpage'))
        
        featureArrayData = jsonFeaturesList[0][2]
    else:
        return redirect(url_for('loginpage'))
    return render_template('configure.html',logo_image = LOGO_PATH, folderArray = jsonFolderList, pointerFolder = folderName, previousPath = "< Back to Scan Templates", featureArray = featureArrayData, functionName = functionNameData, GIF = STEP_PATH)

@app.route('/viewrecord', methods =['GET', 'POST'])
def viewrecordpage():
    if 'loggedin' in session:
        if targetRecord:
            #for user to view all record in selected folder
            jsonFolderList = loadFolder()
            splitData = targetRecord.split("|")
            targetRecordID = splitData[0]
            targetRecordName = splitData[1]
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT RecordDescription,Target,Function,Result,OriginalReport FROM record WHERE RecordID = %s AND RecordName = % s AND UserID = %s', (targetRecordID, targetRecordName,session['UserID'],) )
            recordSQLData = cursor.fetchone()
            resultValue = recordSQLData['Result']
            resultValue = resultValue.replace("'", '"')
            arrayResult = json.dumps(resultValue)
            arrayResult = json.loads(arrayResult)
            functionValue = recordSQLData['Function']
            functionValue = functionValue.replace("'", '"')
            DescriptionValue = recordSQLData['RecordDescription']
            DescriptionValue = DescriptionValue.replace("'", '"')
            ReportValue = recordSQLData['OriginalReport']
            ReportValue = ReportValue.replace("'", '"')
            TargetValue = recordSQLData['Target']
            TargetValue = TargetValue.replace("'", '"')
        else:
            return redirect(url_for('homepage'))
    else:
        return redirect(url_for('loginpage'))
    return render_template('viewrecord.html',logo_image = LOGO_PATH, folderArray = jsonFolderList, pointerFolder = folderName, previousPath = "< Back to Scan Records", selectedRecord = targetRecordName, ResultArray = arrayResult, RecordFunction = functionValue, RecordDescription = DescriptionValue, RecordReport = ReportValue, RecordTarget = TargetValue ) 

@app.route('/viewvulnerability', methods =['GET', 'POST'])
def viewvulnerabilitypage():
    if 'loggedin' in session:
        #for user to view general information of selected vulnerability
        jsonFolderList = loadFolder()
        global target_result
        global target_function
        if request.method == 'POST':
            target_result = request.form['targetResult']
            target_function = request.form['targetFunction']
    else:
        return redirect(url_for('loginpage'))
        
    return render_template('viewvulnerability.html', logo_image=LOGO_PATH, folderArray = jsonFolderList, pointerFolder = folderName, previousPath = "< Back to Scan Hosts", recordArray = target_result, recordFunction = target_function)

@app.route('/viewvulnerabilitydetails', methods =['GET', 'POST'])
def viewvulnerabilitydetailspage():
    if 'loggedin' in session:
        HTMLElement = ''
        search_link = ''
        #for user to view details infomation of selected vulnerability
        jsonFolderList = loadFolder()
        if request.method == 'POST' and 'targetVulnerabilityRecord' in request.form:
            target_vulnerability = request.form['targetVulnerabilityRecord']   
            JSONtarget_vulnerability = json.loads(target_vulnerability)
            CVEID = JSONtarget_vulnerability['CVEID']
            if CVEID:
                search_link = search_URL(JSONtarget_vulnerability['CVEID'])   
                HTMLElement = search_solution(search_link)
        else:
            return redirect(url_for('homepage'))    
    else:
        return redirect(url_for('loginpage'))
    return render_template('viewvulnerabilitydetails.html', logo_image=LOGO_PATH, folderArray = jsonFolderList, pointerFolder = folderName, previousPath = "< Back to Scan Vulnerabilities", recordArray = target_vulnerability, SolutionHTML = HTMLElement, SolutionLink = search_link)

@app.route('/contact', methods =['GET', 'POST'])
def contactpage():
    if 'loggedin' in session:
        #for user to leave a message in contact page
        messagestatus = ''
        if request.method == 'POST' and 'name' in request.form and 'email' in request.form and 'message' in request.form:
            InputName = request.form['name']   
            InputEmail = request.form['email']   
            InputMessage = request.form['message']  

            current_datetime = datetime.now()
            formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            query = "INSERT INTO `message`(`UserName`, `Email`, `Message` ,`TimeDate`) VALUES (%s,%s,%s,%s)"
            values = (InputName,InputEmail,InputMessage,formatted_datetime)
            cursor.execute(query, values)
            mysql.connection.commit()
            messagestatus = 'Sent your message'
    else:
        return redirect(url_for('loginpage'))
    return render_template('contact.html', logo_image=LOGO_PATH, message = messagestatus)

@app.route('/about', methods =['GET', 'POST'])
def aboutpage():

    return render_template('about.html', logo_image=LOGO_PATH, bg_image = BG_PATH, ceo_image = CEO_PATH)

@app.route('/account', methods =['GET', 'POST'])
def accountpage():
    if 'loggedin' in session:
        #for user to reset password in account page
        message = ""
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT UserName,Password FROM users WHERE UserID = %s', (session['UserID'],) )
        SQLData = cursor.fetchall()
        UserName = SQLData[0]['UserName']
        UserPassword = SQLData[0]['Password']
        if request.method == 'POST' and 'defaultpassword' in request.form and 'newpassword' in request.form:
            InputOldPassword = request.form['defaultpassword']   
            inputNewPassword = request.form['newpassword']
            encrptInputOldPassword = xor_encrypt(InputOldPassword,MYKEY)
            if UserPassword == encrptInputOldPassword:
                Encrypt_password = xor_encrypt(inputNewPassword, MYKEY)
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                query = 'UPDATE `users` SET `Password`= %s WHERE UserID = %s'
                values = (Encrypt_password, session['UserID'])
                cursor.execute(query, values)
                mysql.connection.commit()
                message = "Updated password"
            else:
                message = "Invalid password"   
    else:
        return redirect(url_for('loginpage'))
    return render_template('account.html', logo_image=LOGO_PATH, username = UserName, systemmessage = message)
@app.route('/runscript', methods =['GET', 'POST'])
def runscriptpage():

    system_message = ''

    #for CC to view the user password
    # if request.method == 'POST' and 'email' in request.form:
    #     InputEmail= request.form['email']
    #     cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    #     cursor.execute('SELECT Password FROM users WHERE Email = % s ', (InputEmail, ))
    #     SQLData = cursor.fetchone()
    #     UserPassword = SQLData['Password']
    #     system_message = xor_decrypt(UsersPassword,MYKEY)
    decoded_output = '''Starting Nmap 7.80 ( https://nmap.org ) at 2023-07-17 13:56 Malay Peninsula Standard Time
Nmap scan report for 192.168.9.128
Host is up (0.0013s latency).

PORT    STATE SERVICE
80/tcp  open  http
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
443/tcp open  https
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
MAC Address: 00:0C:29:8D:C9:83 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 31.12 seconds
''' 
    # with open("cves\CVE2022.txt", 'r') as file:
    #     json2022CVEData = json.load(file)
    # with open("cves\CVE2021.txt", 'r') as file:
    #     json2021CVEData = json.load(file)
    # with open("cves\CVE2020.txt", 'r') as file:
    #     json2020CVEData = json.load(file)
    # with open("cves\CVE2019.txt", 'r') as file:
    #     json2019CVEData = json.load(file)
    # with open("cves\CVE2018.txt", 'r') as file:
    #     json2018CVEData = json.load(file)
    # with open("cves\CVE2017.txt", 'r') as file:
    #     json2017CVEData = json.load(file)
    # with open("cves\CVE2016.txt", 'r') as file:
    #     json2016CVEData = json.load(file)
    # with open("cves\CVE2015.txt", 'r') as file:
    #     json2015CVEData = json.load(file)
    # with open("cves\CVE2014.txt", 'r') as file:
    #     json2014CVEData = json.load(file)
    # with open("cves\CVE2013.txt", 'r') as file:
    #     json2013CVEData = json.load(file)
    # with open("cves\CVE2012.txt", 'r') as file:
    #     json2012CVEData = json.load(file)
    # with open("cves\CVE2011.txt", 'r') as file:
    #     json2011CVEData = json.load(file)
    # with open("cves\CVE2010.txt", 'r') as file:
    #     json2010CVEData = json.load(file)
    # with open("cves\CVE2009.txt", 'r') as file:
    #     json2009CVEData = json.load(file)
    # with open("cves\CVE2008.txt", 'r') as file:
    #     json2008CVEData = json.load(file)
    # with open("cves\CVE2007.txt", 'r') as file:
    #     json2007CVEData = json.load(file)
    # with open("cves\CVE2006.txt", 'r') as file:
    #     json2012CVEData = json.load(file)
    # with open("cves\CVE2006.txt", 'r') as file:
    #     json2006CVEData = json.load(file)
    # with open("cves\CVE2005.txt", 'r') as file:
    #     json2005CVEData = json.load(file)
    # with open("cves\CVE2004.txt", 'r') as file:
    #     json2004CVEData = json.load(file)
    # with open("cves\CVE2003.txt", 'r') as file:
    #     json2003CVEData = json.load(file)
    # with open("cves\CVE2002.txt", 'r') as file:
    #     json2002CVEData = json.load(file)
    # vulnerabilityDetails = []
    # CriticalAmount=''
    # vulnerabilityList = "" 
    # HighAmount ='' 
    # InfoAmount = ''
    # result = []
    # MediumAmount=''
    # LowAmount=''
    # cve_pattern = r"CVE-\d{4}-\d+"
    # cve_codes = re.findall(cve_pattern, decoded_output)
    # if cve_codes:
    #     vulnerabilityList = [cve for cve in cve_codes if not re.search(r"ERROR|false", cve)]
    
    # smb_pattern = r"smb-vuln-(cve-\d{4}-\d+|ms\d{2}-\d{3})(?:: (true|false|ERROR))?"
    # smb_vulns = re.findall(smb_pattern, decoded_output)

    # if smb_vulns:
    #     for smb_vuln in smb_vulns:
    #         vuln_id, is_vulnerable = smb_vuln
    #         if is_vulnerable != "ERROR" and is_vulnerable != "false":
    #             full_id = f"smb-vuln-{vuln_id}"
    #             vulnerabilityList.append(full_id)
    # uniquevulnerabilityList = list(set(vulnerabilityList))
    # for target_cve in uniquevulnerabilityList:
    #     found = False  
    #     years = re.findall(r"CVE-(\d{4})", target_cve)
        
    #     match years[0]:
    #         case "2022":
    #             CVEFolder = json2022CVEData
    #         case "2021":
    #             CVEFolder = json2021CVEData
    #         case "2020":
    #             CVEFolder = json2020CVEData
    #         case "2019":
    #             CVEFolder = json2019CVEData
    #         case "2018":
    #             CVEFolder = json2018CVEData
    #         case "2017":
    #             CVEFolder = json2017CVEData
    #         case "2016":
    #             CVEFolder = json2016CVEData
    #         case "2015":
    #             CVEFolder = json2015CVEData
    #         case "2014":
    #             CVEFolder = json2014CVEData
    #         case "2013":
    #             CVEFolder = json2013CVEData
    #         case "2012":
    #             CVEFolder = json2012CVEData
    #         case "2011":
    #             CVEFolder = json2011CVEData
    #         case "2010":
    #             CVEFolder = json2010CVEData
    #         case "2009":
    #             CVEFolder = json2009CVEData
    #         case "2008":
    #             CVEFolder = json2008CVEData
    #         case "2007":
    #             CVEFolder = json2007CVEData
    #         case "2006":
    #             CVEFolder = json2006CVEData
    #         case "2005":
    #             CVEFolder = json2005CVEData
    #         case "2004":
    #             CVEFolder = json2004CVEData
    #         case "2003":
    #             CVEFolder = json2003CVEData
    #         case "2002":
    #             CVEFolder = json2002CVEData
    #     for item in CVEFolder:
    #         if item.get('cve', {}).get('CVE_data_meta', {}).get('ID') == target_cve:
    #             found = True
    #             cveID = item['cve']['CVE_data_meta']['ID']
    #             references = item['cve']['references']['reference_data']
    #             description = item['cve']['description']['description_data'][0]['value']
    #             baseScore = item['impact']['baseMetricV3']['cvssV3']['baseScore']
    #             baseSeverity = item['impact']['baseMetricV3']['cvssV3']['baseSeverity']
    #             publishedDate = item['publishedDate']
    #             lastModifiedDate = item['lastModifiedDate']
    #             break

    #     if found:
    #         description = description.replace('"', '')
    #         description = description.replace("'", 'L2G ')
    #         description = description.replace("\\", 'L3G ')
    #         if baseSeverity == "CRITICAL":
    #             CriticalAmount +=1
    #         elif baseSeverity == "HIGH":
    #             HighAmount +=1
    #         elif baseSeverity == "MEDIUM":
    #             MediumAmount +=1
    #         elif baseSeverity == "LOW":
    #             LowAmount +=1
    #         urlList =[]
    #         for ref in references:
    #             urlList.append( ref['url'])
    #         vulnerabilityDetails.append({"CVE ID":cveID,"Description":description,"Base Score":baseScore,"Base Severity":baseSeverity,"Published Date":publishedDate,"Last Modified Date":lastModifiedDate,"References":urlList})
    # if len(vulnerabilityDetails) == 0:
    #     host = {
    #         "Host":"target",
    #         "Critical":0,
    #         "High":0,
    #         "Medium":0,
    #         "Low":0,
    #         "Info":1,
    #         "Total":1,
    #         "Details":'No Vulnerability found'
    #     }
    # else:
    #     host = {
    #         "Host":"target",
    #         "Critical":CriticalAmount,
    #         "High":HighAmount,
    #         "Medium":MediumAmount,
    #         "Low":LowAmount,
    #         "Info":0,
    #         "Total":CriticalAmount + HighAmount + MediumAmount + LowAmount + InfoAmount,
    #         "Details":vulnerabilityDetails
    #     }
    # result.append(host)
    return render_template('runscript.html', logo_image=LOGO_PATH, message = system_message)

#encryption data
def xor_encrypt(plaintext, key):
    ciphertext = ""
    for i in range(len(plaintext)):
        ciphertext += chr(ord(plaintext[i]) ^ ord(key[i % len(key)]))
    return ciphertext

#description data
def xor_decrypt(ciphertext, key):
    return xor_encrypt(ciphertext, key)

#generate random token
def generate_token():
    global reset_token
    reset_token = str(uuid.uuid4())

#send email for user to reset password
def send_password_reset_email(email, reset_token):
    msg = Message('Password Reset', recipients=[email])
    msg.body = f'Click the following link to reset your password: {url_for("resetpasswordpage", token=reset_token, _external=True)}'
    mail.send(msg)

def search_solution(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    banned_table = soup.find_all("table", class_="banded")

    solution = []
    if banned_table is not None:
        for table in banned_table:
            if "update" in table.get_text().lower():
                solution.append(table)
            elif "x86" in table.get_text().lower():
                solution.append(table)
            elif "x64" in table.get_text().lower():
                solution.append(table)   
            elif "fix" in table.get_text().lower():
                solution.append(table)         
    if solution == []:        
        banned_section1 = soup.find("section", attrs={"aria-labelledby": "ID0EDFBD"})  
        if banned_section1:
            solution.append(banned_section1)
    if solution == []:  
        banned_section2 = soup.find("section", attrs={"aria-labelledby": "ID0EFT"})  
        if banned_section2:
            solution.append(banned_section2)
    if solution == []:  
        banned_section3 = soup.find("section", attrs={"aria-labelledby": "ID0EDBBD"})
        if banned_section3:
            solution.append(banned_section3)
    if solution == []: 
        solution.append("N/A")
    return(solution)

def search_URL(query):

    search_url = f"https://support.microsoft.com/en-AU/search/results?query={query}&isEnrichedQuery=false"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    response = requests.get(search_url, headers=headers)
    soup = BeautifulSoup(response.text, "html.parser")
    
    pages_div = soup.find("div", class_="page")
    
    result_links = pages_div.find("a")
    if result_links:
        url = result_links.get("href")
        return url

    return None


if __name__ == "__main__":
    app.debug = True
    app.run()