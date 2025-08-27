from collections import defaultdict
from datetime import datetime

logs = [
        {'date': '2025-08-25T08:12:41', 'host': 'ubuntu', 'process': 'sshd', 'pid': '1350', 'status': 'Accepted', 'user': 'alice', 'ip': '192.168.1.101', 'port': '50321', 'protocol': 'ssh2'}, 
        {'date': '2025-08-25T08:13:02', 'host': 'ubuntu', 'process': 'sshd', 'pid': '1352', 'status': 'Failed', 'user': 'bob', 'ip': '192.168.1.105', 'port': '60411', 'protocol': 'ssh2'}, 
        {'date': '2025-08-25T08:13:04', 'host': 'ubuntu', 'process': 'sshd', 'pid': '1352', 'status': 'Failed', 'user': 'bob', 'ip': '192.168.1.105', 'port': '60411', 'protocol': 'ssh2'}, 
        {'date': '2025-08-25T08:13:07', 'host': 'ubuntu', 'process': 'sshd', 'pid': '1352', 'status': 'Failed', 'user': 'bob', 'ip': '192.168.1.105', 'port': '60411', 'protocol': 'ssh2'}, 
        {'date': '2025-08-25T08:13:10', 'host': 'ubuntu', 'process': 'sshd', 'pid': '1352', 'status': 'Failed', 'user': 'bob', 'ip': '192.168.1.105', 'port': '60411', 'protocol': 'ssh2'}, 
        {'date': '2025-08-25T08:13:12', 'host': 'ubuntu', 'process': 'sshd', 'pid': '1352', 'status': 'Failed', 'user': 'bob', 'ip': '192.168.1.105', 'port': '60411', 'protocol': 'ssh2'}, 
        {'date': '2025-08-25T08:13:13', 'host': 'ubuntu', 'process': 'sshd', 'pid': '1352', 'status': 'Failed', 'user': 'bob', 'ip': '192.168.1.105', 'port': '60411', 'protocol': 'ssh2'}, 
        {'date': '2025-08-25T08:16:10', 'host': 'ubuntu', 'process': 'sshd', 'pid': '1362', 'status': 'Accepted', 'user': 'charlie', 'ip': '192.168.1.102', 'port': '51001', 'protocol': 'ssh2'}, 
        {'date': '2025-08-25T08:17:42', 'host': 'ubuntu', 'process': 'sshd', 'pid': '1365', 'status': 'Failed', 'user': 'root', 'ip': '185.199.110.20', 'port': '33321', 'protocol': 'ssh2'}, 
        {'date': '2025-08-25T08:17:44', 'host': 'ubuntu', 'process': 'sshd', 'pid': '1365', 'status': 'Failed', 'user': 'root', 'ip': '185.199.110.20', 'port': '33321', 'protocol': 'ssh2'},
        {'date': '2025-08-25T08:17:48', 'host': 'ubuntu', 'process': 'sshd', 'pid': '1365', 'status': 'Failed', 'user': 'root', 'ip': '185.199.110.20', 'port': '33321', 'protocol': 'ssh2'}
]

failed_logins = defaultdict(list)


for log in logs:
    if log['status'] ==  'Failed':
        ts = log['date']
        dt = datetime.fromisoformat(ts)
        epoch_time = int(dt.timestamp())
        failed_logins[log['ip']].append(epoch_time)

max_time = 30
attempts = 3
alerts = []

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
                "window_start": time[l],
                "window_end": time[r]
            })
            break
        

print(alerts)




