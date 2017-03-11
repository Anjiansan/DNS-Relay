import subprocess

for i in ['bupt', 'www.baidu.com', 'sina','xyxy68.8u8.net','zelnet.ru']:
    out = subprocess.call("nslookup "+i+" 127.0.0.1",shell=True)
