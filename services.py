import subprocess

site_ports = {'agent.graysale.co': [80, 443, 8888, 22], 'email.graysale.co': [80, 443], 'graysale.co': [80, 443], 'h5.graysale.co': [80, 443, 8888, 22], 'lyncdiscover.graysale.co': [80, 443], 'msoid.graysale.co': [80, 443], 'server.graysale.co': [80, 443, 8888, 22], 'sip.graysale.co': [443], 'www.graysale.co': [80, 443, 8888, 22]}

subdomains = ['agent.graysale.co', 'autodiscover.graysale.co', 'email.graysale.co', 'graysale.co', 'h5.graysale.co', 'lyncdiscover.graysale.co', 'msoid.graysale.co', 'server.graysale.co', 'sip.graysale.co', 'www.graysale.co']

unique_lines = set()

# Loop through each domain and port combination
for domain, ports in site_ports.items():
    for port in ports:
        url = f"http://{domain}:{port}"
        command = ['whatweb', url]
        result = subprocess.run(command, capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if domain in line and line not in unique_lines:
                print(line)
                unique_lines.add(line)

# Loop through each subdomain
for subdomain in subdomains:
    url = f"http://{subdomain}"
    command = ['whatweb', url]
    result = subprocess.run(command, capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if subdomain in line and line not in unique_lines:
            print(line)
            unique_lines.add(line)
