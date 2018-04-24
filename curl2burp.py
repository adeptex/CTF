#!/usr/bin/python3

import json
import os

proxychains_config = '''
strict_chain
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
http	127.0.0.1 8080
'''

with open('proxychains.conf', 'w') as f:
    f.write(proxychains_config)

'''
api.json like 
[{
    'name': 'API Name',
    'command': 'curl --insecure ....'
}]
'''
with open('api.json', 'r') as f:
    methods = json.loads(f.read())

for method in methods:
    print(method['name'])
    os.system('proxychains {}'.format(method['command']))
