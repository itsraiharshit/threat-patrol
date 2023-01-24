# ThreatPatrol: A Simple Vulnerability Scanner Tool for Websites
# Author: Harshit Rai
# Github: https://github.com/itsraiharshit
# Linkedin : https://www.linkedin.com/in/itsraiharshit/
art = '''

___________.__                          __    __________         __                .__   
\__    ___/|  |_________   ____ _____ _/  |_  \______   \_____ _/  |________  ____ |  |  
  |    |   |  |  \_  __ \_/ __ \\__  \\   __\  |     ___/\__  \\   __\_  __ \/  _ \|  |  
  |    |   |   Y  \  | \/\  ___/ / __ \|  |    |    |     / __ \|  |  |  | \(  <_> )  |__
  |____|   |___|  /__|    \___  >____  /__|    |____|    (____  /__|  |__|   \____/|____/
                \/            \/     \/                       \/                         

'''
print(art)
import requests
 
def check_sql_injection(url):
    payload = "'"
    response = requests.get(url + payload)
    if "SQL syntax" in response.text:
        return "SQL injection vulnerability detected!"
    return "No SQL injection vulnerability detected."
 
def check_xss(url):
    payload = "<script>alert('XSS')</script>"
    response = requests.get(url, params={"input": payload})
    if payload in response.text:
        return "XSS vulnerability detected!"
    return "No XSS vulnerability detected."
 
def check_csrf(url):
    csrf_token = ""
    response = requests.get(url)
    if "csrf_token" in response.text:
        csrf_token = response.text.split("csrf_token = ")[1].split(";")[0]
    if csrf_token:
        payload = {"csrf_token": csrf_token}
        response = requests.post(url, data=payload)
        if "Invalid CSRF token" not in response.text:
            return "CSRF vulnerability detected!"
    return "No CSRF vulnerability detected."
 
def check_ssrf(url):
    payload = "http://localhost"
    response = requests.get(url, params={"input": payload})
    if "Error connecting" not in response.text:
        return "SSRF vulnerability detected!"
    return "No SSRF vulnerability detected."
 
def check_lfi(url):
    payload = "../../../etc/passwd"
    response = requests.get(url, params={"file": payload})
    if "root:" in response.text:
        return "LFI vulnerability detected!"
    return "No LFI vulnerability detected."
 
def check_rce(url):
    payload = ";ls"
    response = requests.get(url, params={"input": payload})
    if "bin" in response.text:
        return "RCE vulnerability detected!"
    return "No RCE vulnerability detected."
 
def scan_website(url):
    print(check_sql_injection(url))
    print(check_xss(url))
    print(check_csrf(url))
    print(check_ssrf(url))
    print(check_lfi(url))
    print(check_rce(url))
 
url = input("Enter the website URL you want to scan: ")
try:
    scan_website(url)
except:
    print("Something went wrong")
