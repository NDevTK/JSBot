from urllib.parse import urljoin
import asyncio
import httpx
from re import search
import re
from hashlib import sha256
from bs4 import BeautifulSoup
from sys import argv
from random import shuffle
import sys

seenScripts = set()
checkedURLs = set()
checkedJSURLs = set()
seenLinks = set()

whitelistURLs = set(['https://www.gstatic.com/external_hosted/modernizr/csstransforms3d_csstransitions_search_webp_addtest_shiv_dontmin/modernizr-custom.js', 'https://www.gstatic.com/external_hosted/lottie/lottie.js', 'https://cdn.jsdelivr.net/npm/bootstrap@5.2.1/dist/js/bootstrap.bundle.min.js', 'https://www.google-analytics.com/analytics.js', 'https://ajax.googleapis.com/ajax/libs/jqueryui/1.13.2/jquery-ui.min.js', 'https://ajax.googleapis.com/ajax/libs/jquery/3.6.1/jquery.min.js', 'https://www.gstatic.com/external_hosted/modernizr/modernizr.js', 'https://www.gstatic.com/external_hosted/scrollmagic/ScrollMagic.min.js', 'https://www.gstatic.com/external_hosted/scrollmagic/animation.gsap.min.js', 'https://www.gstatic.com/external_hosted/picturefill/picturefill.min.js', 'https://www.gstatic.com/external_hosted/hammerjs/v2_0_2/hammer.min.js', 'https://www.gstatic.com/external_hosted/gsap/v1_18_0/TweenMax.min.js', 'https://ssl.google-analytics.com/ga.js'])
unsafeOnly = True
allowExternal = True
showErrors = False
showInfo = False
allowRedirects = True
shouldSave = False
formatJS = False
wayback = False
linkMode = False
sinkCheck = True

if formatJS:
    # pip install jsbeautifier
    import jsbeautifier
if wayback:
    # pip install waybackpy
    import waybackpy

limits = httpx.Limits(max_keepalive_connections=100, max_connections=100)
workers = asyncio.Semaphore(100)

# https://github.com/hahwul/RegexPassive
unsafe1 = r"""((src|href|data|location|code|value|action)\s*["'\]]*\s*\+?\s*=)|((replace|assign|navigate|getResponseHeader|open(Dialog)?|showModalDialog|eval|evaluate|execCommand|execScript|setTimeout|setInterval)\s*["'\]]*\s*\()"""
unsafe2 = r"""(location\s*[\[.])|([.\[]\s*["']?\s*(arguments|dialogArguments|innerHTML|write(ln)?|open(Dialog)?|showModalDialog|cookie|URL|documentURI|baseURI|referrer|name|opener|parent|top|content|self|frames)\W)|(localStorage|sessionStorage|Database)"""

sinks = r"""(.*location\.search.*|.*location\.href.*|.*location\.hash.*|.*window\.name.*)"""
link_regex = r"""https?:\/\/[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b[-a-zA-Z0-9()@:%_\+.~#?&//=]*"""

def sha(data):
    return sha256(data.encode()).hexdigest()

def parseJS(js):
    if formatJS:
        return jsbeautifier.beautify(str(js))
    else:
        return str(js)

def isSafe(script):
    if sinkCheck:
        for sink in re.findall(sinks, str(script)):
            if search(unsafe1, str(sink)) or search(unsafe2, str(sink)):
                return False
        return True
    if search(unsafe1, str(script)) or search(unsafe2, str(script)):
        return False
    return True

async def crawl(url, client):
    async with workers:
        try:
            seen = False
            result = await client.get(url)
            url = str(result.url)
            hashedURL = sha(url)
            if hashedURL in checkedURLs:
                return
            checkedURLs.add(hashedURL)

            if 'javascript' in result.headers['content-type']:
                hashedResult = sha(result.text)
                js = parseJS(result.text)
                if hashedResult in seenScripts:
                    return
                seenScripts.add(hashedResult)
                if unsafeOnly and isSafe(js):
                    return
                
                if linkMode:
                    for url2 in re.findall(link_regex, js):
                        hashedLink = sha(url2)
                        if hashedLink in seenLinks:
                            continue
                        print(url2)
                        seenLinks.add(hashedLink)
                else:
                    print(url)
                if shouldSave:
                    with open(hashedURL, 'w') as f:
                        f.write(js+'.js')
                        f.close()
                return

            if 'image' in result.headers['content-type']:
                return

            if 'audio' in result.headers['content-type']:
                return

            if 'video' in result.headers['content-type']:
                return
            
            if 'font' in result.headers['content-type']:
                return
            
            parser = BeautifulSoup(result.text, features='lxml')
            for script in parser.findAll('script'):
                scriptType = script.get('type') or 'application/javascript'
                if scriptType != 'application/javascript' and scriptType != 'application/ecmascript':
                    continue
                if script.get('src') and not allowExternal:
                    continue
                js1 = jsbeautifier.beautify(str(script))
                if not script.get('src') and unsafeOnly and isSafe(script):
                    continue
                if script.get('src'):
                    scriptURL = urljoin(url, script.get('src'))
                    hashedScriptURL = sha(scriptURL)
                    if hashedScriptURL in checkedJSURLs:
                        continue
                    checkedJSURLs.add(hashedScriptURL)
                    if scriptURL in whitelistURLs:
                        continue
                    scriptSRC = await client.get(scriptURL)
                    js2 = parseJS(scriptSRC.text)
                    if isSafe(js2) and unsafeOnly:
                        continue
                    hashedSRC = sha(js2)
                    if hashedSRC in seenScripts:
                        continue
                    seenScripts.add(hashedSRC)
                else:
                    del script['nonce']
                    hashed = sha(js1)
                    if hashed in seenScripts:
                        continue
                    seenScripts.add(hashed)
                if not seen:
                    seen = True
                    print(url)
                    if shouldSave:
                        with open(hashedScriptURL, 'w') as f:
                            f.write(js2+'.js')
                            f.close()
        except KeyboardInterrupt:
            exit()
        except:
            error(url)
def info(msg):
    if (showInfo):
        print('[Info]', msg)

def error(msg):
    if (showErrors):
        print('[Error]', msg)

def waybackBot(urls):
    result = []
    for url in urls:
        wayback = waybackpy.Url(url=url, user_agent='JSBot')
        result += wayback.known_urls(subdomain=True)
        info('WAYBACK added ' + url)
    result = list(set(result))
    return result

async def main():
    if (len(argv) > 1):
        try:
            file = open(argv[1], 'r', encoding='utf8')
            urls = file.readlines()
            file.close()
        except IOError:
            print('Unable to read file')
        else:
            # Make urls unique and shuffled
            urls = list(set(urls))
            if (wayback):
                urls = waybackBot(urls)
            shuffle(urls)
            tasks = []
            info('Starting scan')
            async with httpx.AsyncClient(http2=True, limits=limits, follow_redirects=allowRedirects) as client:
                for url in urls:
                    tasks.append(crawl(url.strip(), client))
                await asyncio.gather(*tasks)
    else:
        error('No file provided')

if __name__ == '__main__':
    try:
        if sys.version_info < (3, 10):
            loop = asyncio.get_event_loop()
        else:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        exit()
