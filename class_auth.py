import math
import requests
import re
from datetime import datetime
from collections import defaultdict

class authLogs_Analyzer:


    def __init__(self, log_file="auth.log"):
        self.log_file = log_file
        self.allowed = ['US', 'CA', 'Unknown']

        self.pattern = re.compile(
        r'(?P<date>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+'
        r'(?P<process>[^\[]+)\[(?P<pid>\d+)\]:\s+'
        r'(?P<status>Accepted|Failed)\s+password\s+for\s+'
        r'(?P<user>\w+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<port>\d+)\s+(?P<protocol>\w+)'
        )
        self.parsed = self.file_parsed()

        ####################################
        self.geo_alerts = []
        self.geo_cache = {}

        ####################################
        self.spray_alerts = []
        self.spray_fields = defaultdict(list)


        ####################################
        self.brute_force_alerts = []

    def file_parsed(self):
        parsed = []
        with open(self.log_file, 'r') as file:
            for lines in file:
                match = self.pattern.match(lines)
                if match:
                    data = match.groupdict()
                    dt = datetime.strptime(data["date"] + " 2025", "%b %d %H:%M:%S %Y")
                    data["date"] = dt.isoformat()
                    parsed.append(data)
        return parsed

    def geo_IP_alert(self,log):
        ip = log['ip']

        if ip in self.geo_cache:
            country = self.geo_cache[ip]
    
        else:
            try:
                res = requests.get(f"https://ipinfo.io/{ip}/json").json()
                country = res.get("country", "Unknown")
                self.geo_cache[ip] = country
            except requests.RequestException as e:
                return {"alert": "GeoIP lookup failed", "ip": ip, "error": str(e)}
        
        if country in self.allowed:
            return None
        else:
            return {
                "alert": "Country is not on allowed list",
                "ip": ip,
                "country": country,
                "Authentication": log['status']
            }
        
    def sprayAttack_alerts(self):
        spray_fields = defaultdict(list)
        sa_alert = []

        for log in self.parsed:
            if log['user'] not in spray_fields[log['ip']]:
                spray_fields[log['ip']].append(log['user'])

        for ip, users in spray_fields.items():
            if len(users) > 1:
               sa_alert.append({
                    "alert": "One IP is attempting to login as multiple users",
                    "ip": ip,
                    "user_accounts": users
                })
        return sa_alert

    def bruteForce_alerts(self):
        failed_logins = defaultdict(list)
        alerts = []

        ## THRESHOLDS
        max_time = 30
        attempts = 3
        
        for log in self.parsed:
            if log['status'] == "Failed":
                ts = log['date']
                dt = datetime.fromisoformat(ts)
                epoch_time = int(dt.timestamp())
                failed_logins[log['ip']].append(epoch_time)

        for ip, time in failed_logins.items():
            time.sort()

            l = 0

            for r in range(len(time)):
                while time[r] - time[l] > max_time:
                    l += 1
                if (r - l + 1) >= attempts:
                    alerts.append({
                        "ip": ip,
                        "attempts": r - l + 1,
                        "window_start": datetime.fromtimestamp(time[l]).isoformat(),
                        "window_end": datetime.fromtimestamp(time[r]).isoformat()
                    })
                    break
        return alerts
        


    def analyze(self):
        for log in self.parsed:
            geo_result = self.geo_IP_alert(log)
          #  if geo_result["alert"] != "GeoIP lookup failed":
            if geo_result:
                self.geo_alerts.append(geo_result)
        
        self.spray_alerts = self.sprayAttack_alerts()

        self.brute_force_alerts = self.bruteForce_alerts()

        return {
            "geo_alerts": self.geo_alerts,
            "spray_alerts": self.spray_alerts,
            "brute_force_alerts": self.brute_force_alerts
        }
            



