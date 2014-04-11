##README:

Dependencies:

1. pyOpenSSL - https://pypi.python.org/pypi/pyOpenSSL
2. Thrift (Py version) - https://pypi.python.org/pypi/thrift 
(install post-extraction)

How to run: (change your cwd to gen-py)

Terminal 1. You need to have the CA live, primarily: `python certificateAuthority.py`

Terminal 2. Run server: goto **gen-py/Node1**
`python node.py Bob s`

Terminal 3. Run legit client: goto **gen-py/Node2**
`python node.py Alice c`

Terminal 4. Run malicious client: goto **gen-py/Node3**
`python node.py Mallory m`

In order to see the outcome of verification, check the o/p on server's Terminal (i.e. Terminal 2) -  this is a bit hack-ish as of now. pyOpenSSL has no straight forward way of doing this, would continue digging for a fix.
