# JSBot
A great bot that finds **unique** JS!  
One usage of this is to help find XSS :)

# Usage
`scan.py urls.txt`

# How to get urls.txt
- Extract from sitemap (https://www.google.com/sitemap.xml)
- Waybackurls (https://github.com/tomnomnom/waybackurls) OR enable 'wayback' in python script.
- Spider (https://github.com/jaeles-project/gospider)

# Requirements
pip install httpx[http2] beautifulsoup4 lxml
