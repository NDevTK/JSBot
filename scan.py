import asyncio
import httpx
from re import match
from hashlib import sha256
from bs4 import BeautifulSoup
from sys import argv
from random import shuffle

seenScripts = set()
seenURLs = set()

whitelistURLs = set(['https://www.gstatic.com/external_hosted/modernizr/csstransforms3d_csstransitions_search_webp_addtest_shiv_dontmin/modernizr-custom.js', 'https://www.gstatic.com/external_hosted/lottie/lottie.js', 'https://cdn.jsdelivr.net/npm/bootstrap@5.2.1/dist/js/bootstrap.bundle.min.js', 'https://www.google-analytics.com/analytics.js', 'https://ajax.googleapis.com/ajax/libs/jqueryui/1.13.2/jquery-ui.min.js', 'https://ajax.googleapis.com/ajax/libs/jquery/3.6.1/jquery.min.js', 'https://www.gstatic.com/external_hosted/modernizr/modernizr.js', 'https://www.gstatic.com/external_hosted/scrollmagic/ScrollMagic.min.js', 'https://www.gstatic.com/external_hosted/scrollmagic/animation.gsap.min.js', 'https://www.gstatic.com/external_hosted/picturefill/picturefill.min.js', 'https://www.gstatic.com/external_hosted/hammerjs/v2_0_2/hammer.min.js', 'https://www.gstatic.com/external_hosted/gsap/v1_18_0/TweenMax.min.js', 'https://ssl.google-analytics.com/ga.js'])
unsafeOnly = True
allowExternal = True
showErrors = False
allowRedirects = True

limits = httpx.Limits(max_keepalive_connections=10, max_connections=10)
workers = asyncio.Semaphore(10)

# https://github.com/hahwul/RegexPassive
unsafe1 = r"""((src|href|data|location|code|value|action)\s*["'\]]*\s*\+?\s*=)|((replace|assign|navigate|getResponseHeader|open(Dialog)?|showModalDialog|eval|evaluate|execCommand|execScript|setTimeout|setInterval)\s*["'\]]*\s*\()"""
unsafe2 = r"""(location\s*[\[.])|([.\[]\s*["']?\s*(arguments|dialogArguments|innerHTML|write(ln)?|open(Dialog)?|showModalDialog|cookie|URL|documentURI|baseURI|referrer|name|opener|parent|top|content|self|frames)\W)|(localStorage|sessionStorage|Database)"""

def sha(data):
    return sha256(data.encode()).hexdigest()

def isSafe(script):
    if match(unsafe1, str(script)) or match(unsafe2, str(script)):
        return False
    return True
    
def parse(url, content):
    parser = BeautifulSoup(content, features='lxml')
    hashedURL = sha(url)
    for script in parser.findAll('script'):
        scriptType = script.get('type') or 'application/javascript'
        if scriptType != 'application/javascript' and scriptType != 'application/ecmascript':
            continue
        if script.get('src') and not allowExternal:
            continue
        if not script.get('src') and unsafeOnly and isSafe(script):
            continue
        if script.get('src') in whitelistURLs:
            continue
        del script['nonce']
        hashed = sha(script)
        if hashed in seenScripts:
            continue
        seenScripts.add(hashed)
        if hashedURL not in seenURLs:
            seenURLs.add(hashedURL)
            print(url)

async def crawl(url, client):
    async with workers:
        try:
            result = await client.get(url)
            parse(str(result.url), result.text)
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
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        exit()
