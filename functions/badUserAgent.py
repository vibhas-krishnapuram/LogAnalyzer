
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

attack_user_agents = [
            "sqlmap",
            "nikto",
            "nessus",
            "burp",
            "w3af",
            "acunetix",
            "netsparker",
            "dirbuster",
            "gobuster",
            "python-requests"
        ]

user_agent_alert = []



for log in logs:
    user_agent = log['user_agent']

    for bad in attack_user_agents:
        if bad.lower() in user_agent.lower():
            user_agent_alert.append(
                {
                "alert": "Potential Malicous Agent",
                "user_agent": user_agent,
                "timestamp": log['datetime']
                })
            

print(user_agent_alert)