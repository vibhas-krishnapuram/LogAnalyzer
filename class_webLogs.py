import re
import json
import urllib.parse
from collections import defaultdict, Counter
from datetime import datetime
import ipaddress

class WebLogScanner:

    def __init__(self):
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

        