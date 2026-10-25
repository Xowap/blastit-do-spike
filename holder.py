"""Secret holder: started with an empty environment, receives the secret on a pipe.

Stands in for blastit's dbproxy. It proves possession by publishing the sha256 of
what it received, keeps the secret in memory, and idles.
"""

import hashlib
import json
import os
import sys
import time

fd = int(sys.argv[1])
chunks = []
while True:
    c = os.read(fd, 4096)
    if not c:
        break
    chunks.append(c)
os.close(fd)
secret = b"".join(chunks)

proof = {"pid": os.getpid(), "uid": os.getuid(), "env_keys": sorted(os.environ),
         "sha256": hashlib.sha256(secret).hexdigest()}
tmp = "/tmp/holder-proof.json.tmp"
with open(tmp, "w") as f:
    json.dump(proof, f)
os.chmod(tmp, 0o644)
os.rename(tmp, "/tmp/holder-proof.json")

while True:
    time.sleep(3600)
