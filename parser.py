import re
from datetime import datetime

log_file = "auth.log"

pattern = re.compile(
    r'(?P<date>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<process>[^\[]+)\[(?P<pid>\d+)\]:\s+'
    r'(?P<status>Accepted|Failed)\s+password\s+for\s+'
    r'(?P<user>\w+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<port>\d+)\s+(?P<protocol>\w+)'
)

parsed = []

with open(log_file, 'r') as file:
    for lines in file:
        match = pattern.match(lines)
        if match:
            data = match.groupdict()
            
            dt = datetime.strptime(data["date"] + " 2025", "%b %d %H:%M:%S %Y")
            data["date"] = dt.isoformat()

            parsed.append(data)
print(parsed)

  
