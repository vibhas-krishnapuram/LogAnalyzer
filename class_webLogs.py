import re
import json
import urllib.parse
from collections import defaultdict, Counter
from datetime import datetime
import ipaddress

class WebLogScanner:

    def __init__(self, log_file="web.log"):

        self.pattern = re.compile(
        r'(?P<ip>\S+) - - \[(?P<datetime>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
        r'(?P<status>\d{3}) (?P<bytes>\d+) '
        r'"[^"]*" "(?P<user_agent>[^"]+)"'
        )  

        self.log_file = log_file
        self.parsed = self.file_parsing()

        self.vulnerability_patterns = {
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

        self.suspicious_status_codes = [400, 401, 403, 404, 500, 502, 503]
        self.attack_user_agents = [
            r"sqlmap",
            r"nikto",
            r"nessus",
            r"burp",
            r"w3af",
            r"acunetix",
            r"netsparker",
            r"dirbuster",
            r"gobuster",
            r"python-requests"
        ]

        ##### ALERT ARRAYS #######
        self.user_agent_alert = []


    def file_parsing(self):
        parsed = []
        with open(self.log_file, 'r') as file:
            for lines in file:
                match = self.pattern.match(lines)
                if match:
                    data = match.groupdict()
                    dt_str = data["datetime"]
                    try:
                        dt = datetime.strptime(dt_str, "%d/%b/%Y:%H:%M:%S %z")
                        data["datetime"] = dt.isoformat()
                    except ValueError:
                        pass
                    parsed.append(data)
        return parsed

    def userAgent_search(self):
        for log in self.parsed:
            user_agent = log['user_agent']

            for bad in self.attack_user_agents:
                if bad.lower() in user_agent.lower():
                    self.user_agent_alert.append(
                        {
                        "alert": "Potential Malicous Agent",
                        "user_agent": user_agent,
                        "timestamp": log['datetime']
                        })
        return self.user_agent_alert