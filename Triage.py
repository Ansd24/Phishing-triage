
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup as bs
from pathlib import Path
import re
import argparse
import openpyxl
import csv




pattern = re.compile(r'''
    [a-zA-Z0-9.+%_-]+
    @
    [a-zA-Z0-9.-]+
    \.[a-zA-Z]{2,}
    ''', re.VERBOSE)




def compare(return_path, sender):
    return return_path == sender
        



#use bs to check the malicious link
def getLinks(msg):
    #extract the html part from the email 
    html_part = msg.get_body(preferencelist=("html",))
    link_list = []
    if html_part is not None:
        html = html_part.get_content()
        soup = bs(html, 'html.parser')
        links = soup.find_all('a', href = True)
        for a in links:
            link_list.append(a['href'])
        return link_list
    else:
        return []

def check_auth(msg):
    auth_results = (msg["Authentication-Results"])
    if auth_results is None:
        return ['no header']
    check_list = []
    for part in auth_results.split():
        if part.startswith(("spf", "dkim", "dmarc")):
            check_list.append(part)
    return check_list



def calculate_score(msg, comparison, urls):
    score = 0
    auth_results = msg["Authentication-Results"]

    if auth_results is None:
        score += 2
    else:
        if "spf=fail" in auth_results:
            score += 2
        if "dkim=fail" in auth_results:
            score += 2
        if "dmarc=fail" in auth_results:
            score += 3

    if comparison == False:
        score += 2

    score += len(urls)
    # print('score is: ', score)
    return score

def verdict(score):
    if score >= 6:
        return '🔴 Likely Phishing' 
    if score >=3:
        return '🟡 Suspcious'
    return '🟢 Safe'

def defang(maliciousURL):
    defanged = []
    for i in maliciousURL:
        new_url = i.replace("http", "hxxp").replace(".", "[.]")
        defanged.append(new_url)
    return defanged


def triage(msg):
    try:
        return_path  = pattern.findall(msg["Return-Path"])[0]
    except(TypeError, IndexError):
        return_path = None
    try:
        sender  = pattern.findall(msg["From"])[0]
    except (TypeError, IndexError):
        sender = None
    mail_to  = (msg["To"])

    #extract potentially malicious url without opening them
    body = msg.get_body(preferencelist=("plain",))
    msg_body = (body.get_content())
    urls = re.findall(r"https?://[^\s\"'<>]+", msg_body)
    
    comparison = compare(return_path, sender)
    links = getLinks(msg)
    auth  = check_auth(msg)
        
    score =  calculate_score(msg, comparison, urls + links)
    verdictResult = verdict(score)
    return {
    "authentication": ",".join(auth),
    "subject": msg["Subject"],
    "sender": sender,
    "return_path": return_path,
    "to": mail_to,
    "urls_found": len(urls + links),
    "score": score,
    "verdict": verdictResult,
}


parser = argparse.ArgumentParser()
parser.add_argument("target", help='a file or a folder')
parser.add_argument("--format", choices=['x', 'csv', 't'], default='csv', help = 'report format (default is csv)')
args = parser.parse_args()
target = Path(args.target)
if target.is_dir():
    files = list(target.glob("*.eml"))
else:
    files = [target]


values_in_results = []
for mail in files:
    with open(mail, "rb") as file:
        msg = BytesParser(policy=policy.default).parse(file)
    result = triage(msg)
    result = {"file": mail.name, **result}
    values_in_results.append(result)


def inTerminal(findings):
    print(f"{'File Name':<16}{'Verdict':<20}  {'Score':>5}")
    print('-' *45)
    for i in findings:
        print(f'{i["file"]:<16}{i["verdict"]:<20}  {i["score"]}')



def inCSV(result):
    with open('Report.csv', 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=result[0].keys())
        writer.writeheader()
        writer.writerows(result)
    print("saved")

def inExcel(results):
    wb = openpyxl.Workbook()
    ws = wb.active
    headers = list(results[0].keys())
    ws.append(headers)
    for row in results:
        ws.append([row[h] for h in headers])
    wb.save('Report.xlsx')
    print('saved report as .xlsx')

if not values_in_results:
    print("No eml file found")
elif args.format == "x":
    inExcel(values_in_results)
elif args.format == "t":
    inTerminal(values_in_results)
else:
    inCSV(values_in_results)