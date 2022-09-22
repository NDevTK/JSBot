import requests
from re import match
from hashlib import sha256
from bs4 import BeautifulSoup
from sys import argv
from random import shuffle

seenScripts = set()
seenURLs = set()
unsafeOnly = True
allowExternal = True

# https://github.com/hahwul/RegexPassive
unsafe1 = r"""((src|href|data|location|code|value|action)\s*["'\]]*\s*\+?\s*=)|((replace|assign|navigate|getResponseHeader|open(Dialog)?|showModalDialog|eval|evaluate|execCommand|execScript|setTimeout|setInterval)\s*["'\]]*\s*\()"""
unsafe2 = r"""(location\s*[\[.])|([.\[]\s*["']?\s*(arguments|dialogArguments|innerHTML|write(ln)?|open(Dialog)?|showModalDialog|cookie|URL|documentURI|baseURI|referrer|name|opener|parent|top|content|self|frames)\W)|(localStorage|sessionStorage|Database)"""

def sha(data):
    return sha256(data.encode()).hexdigest()

def isUnsafe(script):
    if match(unsafe1, str(script)) or match(unsafe2, str(script)):
        return True
    return False
    
def crawl(url):
    result = requests.get(url)
    parser = BeautifulSoup(result.text, features='lxml')
    hashedURL = sha(url)
    for script in parser.findAll('script'):
        scriptType = script.get('type') or 'application/javascript'
        if scriptType != 'application/javascript' and scriptType != 'application/ecmascript':
            continue
        del script['nonce']
        if script.get('src') and not allowExternal:
            continue
        if not script.get('src') and unsafeOnly and not isUnsafe(script):
            continue
        hashed = sha(script)
        if hashed in seenScripts:
            continue
        seenScripts.add(hashed)
        if hashedURL not in seenURLs:
            seenURLs.add(hashedURL)
            print(url)

if (len(argv) > 1):
    try:
        file = open(argv[1], 'r')
        urls = file.readlines()
        file.close()
    except IOError:
        print('Unable to read file')
    else:
        # Make urls unique and shuffled
        urls = list(set(urls))
        shuffle(urls)
        for url in urls:
            crawl(url.strip())
else:
    print('No file provided')
