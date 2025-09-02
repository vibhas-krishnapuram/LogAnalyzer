from importlib.resources import path
import re 

logs = [
{'ip': '192.168.1.10', 'datetime': '2025-08-31T14:23:01-04:00', 'method': 'GET', 'path': '/index.html', 'protocol': 'HTTP/1.1', 'status': '200', 'bytes': '5120', 'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}, 
{'ip': '203.0.113.45', 'datetime': '2025-08-31T14:23:15-04:00', 'method': 'GET', 'path': '/login.php', 'protocol': 'HTTP/1.1', 'status': '200', 'bytes': '1024', 'user_agent': 'Mozilla/5.0'}, 
{'ip': '198.51.100.23', 'datetime': '2025-08-31T14:23:42-04:00', 'method': 'POST', 'path': '/login.php', 'protocol': 'HTTP/1.1', 'status': '401', 'bytes': '420', 'user_agent': 'Mozilla/5.0'}, 
{'ip': '198.51.100.77', 'datetime': '2025-08-31T14:25:36-04:00', 'method': 'GET', 'path': '/admin', 'protocol': 'HTTP/1.1', 'status': '301', 'bytes': '250', 'user_agent': 'burp/1.4.7#dev'},   
{'ip': '203.0.113.50', 'datetime': '2025-08-31T14:24:05-04:00', 'method': 'GET', 'path': '/wp-admin/', 'protocol': 'HTTP/1.1', 'status': '403', 'bytes': '720', 'user_agent': 'Mozilla/5.0 (Linux; Android 11)'}, 
{'ip': '192.0.2.15', 'datetime': '2025-08-31T14:24:44-04:00', 'method': 'GET', 'path': '/../../etc/passwd', 'protocol': 'HTTP/1.1', 'status': '400', 'bytes': '300', 'user_agent': 'curl/7.68.0'}, 
{'ip': '203.0.113.99', 'datetime': '2025-08-31T14:25:12-04:00', 'method': 'GET', 'path': '/search.php?q=<script>alert(1)</script>', 'protocol': 'HTTP/1.1', 'status': '200', 'bytes': '950', 'user_agent': 'Mozilla/5.0'}, 
{'ip': '198.51.100.77', 'datetime': '2025-08-31T14:25:36-04:00', 'method': 'GET', 'path': '/admin', 'protocol': 'HTTP/1.1', 'status': '301', 'bytes': '250', 'user_agent': 'sqlmap/1.4.7#dev'}   
]

vulnerability_patterns = {
            'sql_injection': [
                r"'.*(?:union|select|insert|delete|drop|update).*--",
                r"1=1",
                r"' or '1'='1",
                r"(?:union|select).*(?:from|information_schema)",
                r"benchmark\(",
                r"sleep\(\d+\)",
                r"waitfor\s+delay"
            ],
            'xss': [
                r"<script.*?>.*?</script>",
                r"javascript:",
                r"on(?:load|error|click|mouseover)\s*=",
                r"<iframe.*?>",
                r"document\.cookie",
                r"alert\(",
                r"eval\("
            ],
            'path_traversal': [
                r"\.\.[\\/]",
                r"(?:\.\.[\\/]){2,}",
                r"[\\/]etc[\\/]passwd",
                r"[\\/]windows[\\/]system32",
                r"\.\.%2f",
                r"%2e%2e%2f"
            ],
            'command_injection': [
                r";\s*(?:cat|ls|pwd|whoami|id|uname)",
                r"\|\s*(?:cat|ls|pwd|whoami|id|uname)",
                r"&&\s*(?:cat|ls|pwd|whoami|id|uname)",
                r"`.*`",
                r"\$\(.*\)"
            ],
            'ldap_injection': [
                r"\*\)\(.*=",
                r"\)\(.*\*",
                r"\(\|.*\)",
                r"\(&.*\)"
            ],
            'file_inclusion': [
                r"(?:file|php|data|ftp|http|https)://",
                r"\.php\?.*=(?:file|php|data)://",
                r"include.*=.*\.\./",
                r"require.*=.*\.\./",
                r"wrapper.*file://"
            ]
        }


compiled_vulnerability_patterns = {
    vuln: [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    for vuln, patterns in vulnerability_patterns.items()
}

vuln_alert = []

for log in logs:
    pathh = log.get("path")
    if not pathh:
        continue

    for vuln, patterns in compiled_vulnerability_patterns.items():
        for pattern in patterns:
            if pattern.search(pathh):   # faster, no recompile each time
                vuln_alert.append({
                    "alert": "Web App Vulnerability",
                    "ip_address": log["ip"],
                    "vulnerability": vuln,
                    "type": pattern.pattern,  # get original string back
                    "path": pathh
                })
                break

print(vuln_alert)
