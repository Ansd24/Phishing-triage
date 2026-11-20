
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup as bs
from pathlib import Path
import re
import sys
import glob







pattern = re.compile(r'''
    [a-zA-Z0-9.+%_-]+
    @
    [a-zA-Z0-9.-]+
    \.[a-zA-Z]{2,}
    ''', re.VERBOSE)




def compare(return_path, sender, mail_to):
    if return_path != sender:
        print(" Warning: retrun path does not match the sender address")
    print("return path is:", return_path,"\n","sender is: ", sender,"\n","mail sent to: ", mail_to)



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
        print("no authentication results header")
        return
    for part in auth_results.split():
        if part.startswith(("spf", "dkim", "dmarc")):
            print(part)




def calculate_score(msg, return_path, sender, urls):
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

    if return_path != sender:
        score += 2

    score += len(urls)
    print('score is: ', score)
    return verdict(score)

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
        print('no return path specified')
    try:
        sender  = pattern.findall(msg["From"])[0]
    except (TypeError, IndexError):
        sender = None
    mail_to  = (msg["To"])

    #extract potentially malicious url without opening them
    body = msg.get_body(preferencelist=("plain",))
    msg_body = (body.get_content())
    urls = re.findall(r"https?://[^\s\"'<>]+", msg_body)
    
    safe_urls = defang(urls)
    for u in safe_urls:
        print(u)
    compare(return_path, sender, mail_to)
    links = getLinks(msg)
    check_auth(msg)
        
    return calculate_score(msg, return_path, sender, urls + links)


target = Path(sys.argv[1])

if target.is_dir():
    files = list(target.glob("*.eml"))
else:
    files = [target]

for mail in files:
    with open(mail, "rb") as file:
        
        msg = BytesParser(policy=policy.default).parse(file)
    print("--------"* 20)
    print(file.name)
    result = triage(msg)
    print(result)
    

