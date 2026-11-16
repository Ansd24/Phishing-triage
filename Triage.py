from email import policy
from email.parser import BytesParser
import re
from bs4 import BeautifulSoup as bs


mail = "sample_04.html"
with open(mail, "rb") as file:
        msg = BytesParser(policy=policy.default).parse(file)




#extract the html part from the email 
html_part = msg.get_body(preferencelist=("html",))


pattern = re.compile(r'''
    [a-zA-Z0-9.+%_-]+
    @
    [a-zA-Z0-9.-]+
    \.[a-zA-Z]{2,}
    ''', re.VERBOSE)

try:
    return_path  = pattern.findall(msg["Return-Path"])[0]
except(TypeError, IndexError):
    return_path = None
    print('no return path specified')
sender  = pattern.findall(msg["From"])[0]
mail_to  = (msg["To"])



def check_auth():
    list_auth = []
    auth_results = (msg["Authentication-Results"])
    if auth_results is None:
        print("no authentication results header")
        return
    else:
        compare()
    parts = auth_results.split()
    for part in parts:
        if (part.startswith(('spf', 'dkim', 'dmarc'))):
            print(part)



def compare():
    if return_path != sender:
        print(" Warning: retrun path does not match the sender address")
    print("return path is:", return_path,"\n","sender is: ", sender,"\n","mail sent to: ", mail_to)

def defang(maliciousURL):
    defanged = []
    for i in maliciousURL:
        new_url = i.replace("http", "hxxp").replace(".", "[.]")
        defanged.append(new_url)
    return defanged


#extract potentially malicious url without opening them
body = msg.get_body(preferencelist=("plain",))
msg_body = (body.get_content())
urls = re.findall(r"https?://[^\s\"'<>]+", msg_body)
defang(urls)
safe_urls = defang(urls)
for u in safe_urls:
    print(u)




#use bs to check the malicious link
def getLinks():
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


def calculate_score():
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
    return verdict(score)



def verdict(score):
    if score >= 6:
        return '🔴'
    if score >=3:
        return '🟡'
    return '🟢'







check_auth()

print('score:',calculate_score())