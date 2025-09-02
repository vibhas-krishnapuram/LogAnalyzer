import re 
from datetime import datetime


pattern = re.compile(
        r'(?P<ip>\S+) - - \[(?P<datetime>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
        r'(?P<status>\d{3}) (?P<bytes>\d+) '
        r'"[^"]*" "(?P<user_agent>[^"]+)"'
        )  

parsed = []

with open("web.log", 'r') as file:
    for lines in file:
        match = pattern.match(lines)
        if match:
            data = match.groupdict()
            dt_str = data["datetime"]
            try:
                dt = datetime.strptime(dt_str, "%d/%b/%Y:%H:%M:%S %z")
                data["datetime"] = dt.isoformat()
            except ValueError:
                    pass
            parsed.append(data)

#print(parsed)