from collections import defaultdict

logs = [
        {'date': '2025-08-25T08:12:41', 'host': 'ubuntu', 'process': 'sshd', 'pid': '1350', 'status': 'Accepted', 'user': 'alice', 'ip': '103.102.220.5', 'port': '50321', 'protocol': 'ssh2'}, 
        {'date': '2025-08-25T08:13:02', 'host': 'ubuntu', 'process': 'sshd', 'pid': '1352', 'status': 'Failed', 'user': 'bob', 'ip': '192.168.1.105', 'port': '60411', 'protocol': 'ssh2'}, 
        {'date': '2025-08-25T08:13:04', 'host': 'ubuntu', 'process': 'sshd', 'pid': '1352', 'status': 'Failed', 'user': 'bob', 'ip': '192.168.1.105', 'port': '60411', 'protocol': 'ssh2'}, 
        {'date': '2025-08-25T08:13:07', 'host': 'ubuntu', 'process': 'sshd', 'pid': '1352', 'status': 'Failed', 'user': 'bob', 'ip': '192.168.1.105', 'port': '60411', 'protocol': 'ssh2'}, 
        {'date': '2025-08-25T08:13:10', 'host': 'ubuntu', 'process': 'sshd', 'pid': '1352', 'status': 'Failed', 'user': 'bob', 'ip': '192.168.1.105', 'port': '60411', 'protocol': 'ssh2'}, 
        {'date': '2025-08-25T08:13:12', 'host': 'ubuntu', 'process': 'sshd', 'pid': '1352', 'status': 'Failed', 'user': 'bob', 'ip': '103.102.220.12', 'port': '60411', 'protocol': 'ssh2'}, 
        {'date': '2025-08-25T08:13:13', 'host': 'ubuntu', 'process': 'sshd', 'pid': '1352', 'status': 'Failed', 'user': 'bob', 'ip': '192.168.1.105', 'port': '60411', 'protocol': 'ssh2'}, 
        {'date': '2025-08-25T08:16:10', 'host': 'ubuntu', 'process': 'sshd', 'pid': '1362', 'status': 'Accepted', 'user': 'charlie', 'ip': '192.168.1.102', 'port': '51001', 'protocol': 'ssh2'}, 
        {'date': '2025-08-25T08:17:42', 'host': 'ubuntu', 'process': 'sshd', 'pid': '1365', 'status': 'Failed', 'user': 'root', 'ip': '185.199.110.20', 'port': '33321', 'protocol': 'ssh2'}, 
        {'date': '2025-08-25T08:17:44', 'host': 'ubuntu', 'process': 'sshd', 'pid': '1365', 'status': 'Failed', 'user': 'root', 'ip': '185.199.110.20', 'port': '33321', 'protocol': 'ssh2'},
        {'date': '2025-08-25T08:17:48', 'host': 'ubuntu', 'process': 'sshd', 'pid': '1365', 'status': 'Failed', 'user': 'root', 'ip': '103.102.220.5', 'port': '33321', 'protocol': 'ssh2'},
        {'date': '2025-08-25T08:17:48', 'host': 'ubuntu', 'process': 'sshd', 'pid': '1365', 'status': 'Failed', 'user': 'root', 'ip': '8.8.8.8', 'port': '33321', 'protocol': 'ssh2'}
]

spray_fields = defaultdict(list)
alert = []

for log in logs:
    if log['user'] not in spray_fields[log['ip']]:
        spray_fields[log['ip']].append(log['user'])

for ip, users in spray_fields.items():
    if len(users) > 1:
        alert.append({
            "alert": "One IP is attempting to login as multiple users",
            "ip": ip,
            "user_accounts": users
        })
