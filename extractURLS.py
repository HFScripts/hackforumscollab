import asyncio
import ssl
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import aiohttp

site_ports = {
    'agent.graysale.co': [80, 443, 8888, 22],
    'graysale.co': [80, 443],
    'h5.graysale.co': [80, 443, 8888, 22],
    'server.graysale.co': [80, 443, 8888, 22],
    'www.graysale.co': [80, 443, 8888, 22]
}

async def extract_links_and_files(url, ssl_context=None):
    local_files = set()

    try:
        timeout = aiohttp.ClientTimeout(total=10)
        connector = aiohttp.TCPConnector(ssl=ssl_context)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    text = await response.text()
                    soup = BeautifulSoup(text, 'html.parser')

                    for link in soup.find_all(['a', 'link', 'script'], href=True):
                        parsed_link = urlparse(link['href'])

                        if parsed_link.netloc == '' or parsed_link.netloc == urlparse(url).netloc:
                            local_files.add(urljoin(url, link['href']))

                    for script in soup.find_all('script', src=True):
                        parsed_script = urlparse(script['src'])

                        if parsed_script.netloc == '' or parsed_script.netloc == urlparse(url).netloc:
                            local_files.add(urljoin(url, script['src']))

    except Exception:
        pass

    return local_files

async def main():
    tasks = []

    for domain, ports in site_ports.items():
        for port in ports:
            for protocol in ['http', 'https']:
                url = f"{protocol}://{domain}:{port}/"
                if protocol == 'http':
                    tasks.append(asyncio.ensure_future(extract_links_and_files(url)))
                else:
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                    tasks.append(asyncio.ensure_future(extract_links_and_files(url, ssl_context=ssl_context)))

    results = await asyncio.gather(*tasks)

    extracted_urls = []


    for res in results:
        if res:
            for url in res:
                parsed_url = urlparse(url)
                if parsed_url.scheme and parsed_url.netloc:
                    extracted_urls.append(url)

    extracted_urls = list(set(extracted_urls))
    print(extracted_urls)
asyncio.run(main())
