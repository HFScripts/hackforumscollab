import re
import requests
import dns.resolver
from bs4 import BeautifulSoup
import concurrent.futures
import tldextract
import json
from shodan import Shodan
from requests.exceptions import ReadTimeout
import socket
from ipaddress import ip_address, ip_network


#Set these variables to your setup. All apis are free, just register and paste it in.
securitytrails_api_key = "1"
shodan_api_key = "1"
virustotal_api_key = "1"
domain = "graysale.co"

def get_subdomains_from_securitytrails(domain, api_key):
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": api_key}
    response = requests.get(url, headers=headers, timeout=10)
    
    if response.status_code == 200:
        data = json.loads(response.text)
        subdomains = set()
        for subdomain in data['subdomains']:
            subdomains.add(f"{subdomain}.{domain}")
        return subdomains
    else:
        print(f"No data returned or API key not set from SecurityTrails API")
        return set()

def get_subdomains_from_virustotal(domain, api_key):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers, timeout=10)
    
    if response.status_code == 200:
        data = json.loads(response.text)
        subdomains = set()
        for item in data['data']:
            subdomains.add(item['id'])
        return subdomains
    else:
        print(f"No data returned or API key not set from VirusTotal API for domain {domain}")
        return set()

def get_subdomains_from_shodan(domain, api_key):
    api = Shodan(api_key)
    try:
        results = api.search(f"hostname:{domain}")
        subdomains = set()
        for result in results['matches']:
            subdomains.add(result['hostnames'][0])
        return subdomains
    except Exception as e:
        print(f"Error with Shodan API: {e}")
        return set()

def get_subdomains_from_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200 and response.text.strip():
            data = response.json()
            subdomains = set()
            for item in data:
                name_value = item['name_value']
                if re.match(r'^[\w.-]+\.[a-zA-Z]{2,}$', name_value):
                    subdomains.add(name_value)
            return subdomains
        else:
            print(f"No data returned or API key not set from crt.sh for domain {domain}")
            return set()
    except ReadTimeout:
        print(f"Timeout error while connecting to crt.sh for domain {domain}")
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

def get_subdomains(domain, securitytrails_api_key, shodan_api_key, virustotal_api_key):
    if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
        print(f"Invalid domain: {domain}")
        return []

    methods = [
        get_subdomains_from_crtsh,
        get_subdomains_from_dns,
        get_subdomains_from_website,
        lambda domain: get_subdomains_from_securitytrails(domain, securitytrails_api_key),
        lambda domain: get_subdomains_from_shodan(domain, shodan_api_key),
        lambda domain: get_subdomains_from_virustotal(domain, virustotal_api_key),
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

subdomains = get_subdomains(domain, securitytrails_api_key, shodan_api_key, virustotal_api_key)
print("\nAll Subdomains Discovered:")
print(subdomains)

# List of Cloudflare IP ranges
cloudflare_ips = [
    '173.245.48.0/20',
    '103.21.244.0/22',
    '103.22.200.0/22',
    '103.31.4.0/22',
    '141.101.64.0/18',
    '108.162.192.0/18',
    '190.93.240.0/20',
    '188.114.96.0/20',
    '197.234.240.0/22',
    '198.41.128.0/17',
    '162.158.0.0/15',
    '104.16.0.0/12',
    '172.64.0.0/13',
    '131.0.72.0/22'
]

def is_cloudflare_ip(ip):
    for cidr in cloudflare_ips:
        if ip_address(ip) in ip_network(cidr):
            return True
    return False

def check_subdomains(subdomains):
    no_cloudflare = []
    cloudflare = []

    for subdomain in subdomains:
        try:
            ip = socket.gethostbyname(subdomain)
            if is_cloudflare_ip(ip):
                cloudflare.append(subdomain)
            else:
                no_cloudflare.append(subdomain)
        except socket.gaierror:
            pass

    return no_cloudflare, cloudflare

no_cloudflare, cloudflare = check_subdomains(subdomains)
print("\nSubdomains without Cloudflare:")
print(no_cloudflare)
print("\nSubdomains with Cloudflare:")
print(cloudflare)
