from requests import get
from re import match
from hashlib import sha256
from bs4 import BeautifulSoup
from sys import argv
from random import shuffle

seenScripts = set()
seenURLs = set()

whitelistURLs = set(['https://cdn.jsdelivr.net/npm/bootstrap@5.2.1/dist/js/bootstrap.bundle.min.js', 'https://www.google-analytics.com/analytics.js', 'https://ajax.googleapis.com/ajax/libs/jqueryui/1.13.2/jquery-ui.min.js', 'https://ajax.googleapis.com/ajax/libs/jquery/3.6.1/jquery.min.js', 'https://www.gstatic.com/external_hosted/modernizr/modernizr.js', 'https://www.gstatic.com/external_hosted/scrollmagic/ScrollMagic.min.js', 'https://www.gstatic.com/external_hosted/scrollmagic/animation.gsap.min.js', 'https://www.gstatic.com/external_hosted/picturefill/picturefill.min.js', 'https://www.gstatic.com/external_hosted/hammerjs/v2_0_2/hammer.min.js', 'https://www.gstatic.com/external_hosted/gsap/v1_18_0/TweenMax.min.js', 'https://ssl.google-analytics.com/ga.js'])
unsafeOnly = True
allowExternal = True
skipError = True

# https://github.com/hahwul/RegexPassive
unsafe1 = r"""((src|href|data|location|code|value|action)\s*["'\]]*\s*\+?\s*=)|((replace|assign|navigate|getResponseHeader|open(Dialog)?|showModalDialog|eval|evaluate|execCommand|execScript|setTimeout|setInterval)\s*["'\]]*\s*\()"""
unsafe2 = r"""(location\s*[\[.])|([.\[]\s*["']?\s*(arguments|dialogArguments|innerHTML|write(ln)?|open(Dialog)?|showModalDialog|cookie|URL|documentURI|baseURI|referrer|name|opener|parent|top|content|self|frames)\W)|(localStorage|sessionStorage|Database)"""

def sha(data):
    return sha256(data.encode()).hexdigest()

def isSafe(script):
    if match(unsafe1, str(script)) or match(unsafe2, str(script)):
        return False
    return True
    
def crawl(url):
    result = get(url)
    parser = BeautifulSoup(result.text, features='lxml')
    hashedURL = sha(url)
    for script in parser.findAll('script'):
        scriptType = script.get('type') or 'application/javascript'
        if scriptType != 'application/javascript' and scriptType != 'application/ecmascript':
            continue
        del script['nonce']
        if script.get('src') and not allowExternal:
            continue
        if not script.get('src') and unsafeOnly and isSafe(script):
            continue
        if script.get('src') in whitelistURLs:
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
            try:
                crawl(url.strip())
            except KeyboardInterrupt:
                exit()
            except:
                if skipError:
                    continue
                else:
                    exit()
else:
    print('No file provided')
