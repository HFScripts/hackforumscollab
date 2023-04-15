import re
import requests
import dns.resolver
from bs4 import BeautifulSoup
import concurrent.futures
import tldextract

def get_subdomains_from_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    response = requests.get(url, timeout=10)
    if response.status_code == 200 and response.text.strip():
        data = response.json()
        subdomains = set()
        for item in data:
            name_value = item['name_value']
            if re.match(r'^[\w.-]+\.[a-zA-Z]{2,}$', name_value):
                subdomains.add(name_value)
        return subdomains
    else:
        print(f"No data returned from crt.sh for domain {domain}")
        return set()

def get_subdomains_from_dns(domain):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '8.8.4.4']
    subdomains = set()
    for record_type in ['A', 'AAAA', 'CNAME']:
        try:
            answers = resolver.resolve(domain, record_type, lifetime=10)
            for answer in answers:
                answer_text = answer.to_text()
                if record_type == 'A' and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', answer_text):
                    # ignore IP addresses that don't correspond to subdomains
                    continue
                elif record_type == 'AAAA' and answer_text.startswith('::'):
                    # ignore IPv6 addresses that don't correspond to subdomains
                    continue
                elif record_type in ['A', 'AAAA']:
                    if domain in answer_text:
                        subdomains.add(answer_text)
                else:
                    if domain in str(answer.target):
                        subdomains.add(str(answer.target))
        except dns.exception.DNSException:
            pass
    return subdomains

def get_subdomains_from_website(domain):
    subdomains = set()
    for protocol in ['http', 'https']:
        try:
            response = requests.get(f"{protocol}://{domain}", timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                extracted = tldextract.extract(href)
                if extracted.subdomain.endswith(domain):
                    subdomains.add(extracted.subdomain)
        except requests.exceptions.RequestException:
            pass
    return subdomains

def get_subdomains(domain):
    if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
        print(f"Invalid domain: {domain}")
        return []

    methods = [
        get_subdomains_from_crtsh,
        get_subdomains_from_dns,
        get_subdomains_from_website
    ]

    all_subdomains = set()
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(method, domain) for method in methods]
        for future in concurrent.futures.as_completed(futures):
            try:
                subdomains = future.result()
                all_subdomains.update(subdomains)
            except Exception as e:
                print(f"Error with {future}: {e}")

    all_subdomains.add(domain)  # add domain to set of subdomains
    return sorted(list(all_subdomains))


domain = "hackforums.net"
subdomains = get_subdomains(domain)
print(subdomains)
