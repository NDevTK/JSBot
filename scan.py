import requests
from hashlib import sha256
from bs4 import BeautifulSoup
from sys import argv
from random import shuffle

seenScripts = set()
seenURLs = set()

def sha(data):
    return sha256(data.encode()).hexdigest()

def crawl(url):
    result = requests.get(url)
    parser = BeautifulSoup(result.text, features='lxml')
    for script in parser.findAll('script'):
        scriptType = script.get('type') or 'application/javascript'
        if scriptType != 'application/javascript' and scriptType != 'application/ecmascript':
            continue
        del script['nonce']
        hashed = sha(script)
        if hashed in seenScripts:
            continue
        seenScripts.add(hashed)
        hashedURL = sha(url)
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
