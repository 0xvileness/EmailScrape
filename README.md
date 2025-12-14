EmailScrape reconnaissance tool that systematically crawls websites and their subdirectories to extract valid email addresses. Unlike generic web scrapers, it employs advanced validation algorithms to filter out false positives and identify legitimate contact information.








Install Dependencies

 pip install requests beautifulsoup4 tldextract colorama


 USAGE

Basic Command

  python3 emailscrape.py https://example.com
Deep Reconnaissance With Custom Limits

python3 emailscrape.py https://example.com --max-pages 500 --max-depth 4
With Proxy For Operational Security

 python3 emailscrape.py https://example.com --proxy http://127.0.0.1:8080
Custom Output And Faster Crawling

 python3 emailscrape.py https://example.com --delay 0.5
