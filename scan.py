from urllib.parse import urljoin
import asyncio
import httpx
from re import search
import re
from hashlib import sha256
from bs4 import BeautifulSoup
from sys import argv
from random import shuffle
import jsbeautifier

seenScripts = set()
checkedURLs = set()
checkedJSURLs = set()
seenLinks = set()

whitelistURLs = set(['https://www.gstatic.com/external_hosted/modernizr/csstransforms3d_csstransitions_search_webp_addtest_shiv_dontmin/modernizr-custom.js', 'https://www.gstatic.com/external_hosted/lottie/lottie.js', 'https://cdn.jsdelivr.net/npm/bootstrap@5.2.1/dist/js/bootstrap.bundle.min.js', 'https://www.google-analytics.com/analytics.js', 'https://ajax.googleapis.com/ajax/libs/jqueryui/1.13.2/jquery-ui.min.js', 'https://ajax.googleapis.com/ajax/libs/jquery/3.6.1/jquery.min.js', 'https://www.gstatic.com/external_hosted/modernizr/modernizr.js', 'https://www.gstatic.com/external_hosted/scrollmagic/ScrollMagic.min.js', 'https://www.gstatic.com/external_hosted/scrollmagic/animation.gsap.min.js', 'https://www.gstatic.com/external_hosted/picturefill/picturefill.min.js', 'https://www.gstatic.com/external_hosted/hammerjs/v2_0_2/hammer.min.js', 'https://www.gstatic.com/external_hosted/gsap/v1_18_0/TweenMax.min.js', 'https://ssl.google-analytics.com/ga.js'])
unsafeOnly = True
allowExternal = True
showErrors = False
allowRedirects = True
shouldSave = False

linkMode = False
sinkCheck = True

limits = httpx.Limits(max_keepalive_connections=100, max_connections=100)
workers = asyncio.Semaphore(100)

# https://github.com/hahwul/RegexPassive
unsafe1 = r"""((src|href|data|location|code|value|action)\s*["'\]]*\s*\+?\s*=)|((replace|assign|navigate|getResponseHeader|open(Dialog)?|showModalDialog|eval|evaluate|execCommand|execScript|setTimeout|setInterval)\s*["'\]]*\s*\()"""
unsafe2 = r"""(location\s*[\[.])|([.\[]\s*["']?\s*(arguments|dialogArguments|innerHTML|write(ln)?|open(Dialog)?|showModalDialog|cookie|URL|documentURI|baseURI|referrer|name|opener|parent|top|content|self|frames)\W)|(localStorage|sessionStorage|Database)"""

sinks = r"""(location\.search|location\.href|location\.hash|window\.name)"""
link_regex = r"""https?:\/\/[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b[-a-zA-Z0-9()@:%_\+.~#?&//=]*"""

def sha(data):
    return sha256(data.encode()).hexdigest()

def isSafe(script):
    if sinkCheck:
        for sink in re.findall(sinks, str(script)):
            if search(unsafe1, str(script)) or search(unsafe2, str(script)):
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
                result.text = jsbeautifier.beautify(result.text)
                if hashedResult in seenScripts:
                    return
                seenScripts.add(hashedResult)
                if unsafeOnly and isSafe(result.text):
                    return
                
                if linkMode:
                    for url2 in re.findall(link_regex, result.text):
                        hashedLink = sha(url2)
                        if hashedLink in seenLinks:
                            continue
                        print(url2)
                        seenLinks.add(hashedLink)
                else:
                    print(url)
                if shouldSave:
                    with open(hashedURL, 'w') as f:
                        f.write(result.text)
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
                script = jsbeautifier.beautify(str(script))
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
                    result.text = jsbeautifier.beautify(scriptSRC.text)
                    if isSafe(scriptSRC.text) and unsafeOnly:
                        continue
                    hashedSRC = sha(scriptSRC.text)
                    if hashedSRC in seenScripts:
                        continue
                    seenScripts.add(hashedSRC)
                else:
                    del script['nonce']
                    hashed = sha(script)
                    if hashed in seenScripts:
                        continue
                    seenScripts.add(hashed)
                if not seen:
                    seen = True
                    print(url)
                    if shouldSave:
                        with open(hashedScriptURL, 'w') as f:
                            f.write(script)
                            f.close()
        except KeyboardInterrupt:
            exit()
        except:
            if showErrors:
                print('[Error]', url)

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
            shuffle(urls)
            tasks = []
            async with httpx.AsyncClient(http2=True, limits=limits, follow_redirects=allowRedirects) as client:
                for url in urls:
                    tasks.append(crawl(url.strip(), client))
                await asyncio.gather(*tasks)
    else:
        print('No file provided')

if __name__ == '__main__':
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        exit()
