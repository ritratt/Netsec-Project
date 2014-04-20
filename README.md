##README:

###PKI Simulation
Using this suite, it is possible to simulate public key infrastructure - commonly employed for distributing certificates. In the current arrangement, there are two key entities - certificate authority (`CA`) and `node` (which can behave as either a server or client - depending on the arguments passed via command-line). The `CA` is centralized in nature - only one `CA` exists for the entire setup. Any node which intends to have a secure communication with its peer, needs to get a certificate issued by the `CA`. In the current setup, the `server` node is responsible for verifying the certificates presented by `client`(s). The server node verifies the certificate using `CA`'s certificate as reference - should the certificate be issued by the centralized `CA`, the certificate will be verified and the server node's bash will output an appropriate signal. If the certificate was not issued by the centralized `CA`, error message would be output to server's bash. All the communication among different nodes and the `CA` takes place via Remote Procedure Calls (RPC) - facilitated using Apache Thrift. 

Dependencies:

1. pyOpenSSL - https://pypi.python.org/pypi/pyOpenSSL
2. Thrift (Py version) - https://pypi.python.org/pypi/thrift 
(install post-extraction)

How to run: (change your cwd to gen-py)

Terminal 1. You need to have the CA live, primarily: `python certificateAuthority.py`

Terminal 2. Run server: goto **gen-py/Node1**
`python node.py Bob s`

Terminal 3. Run legit client: goto **gen-py/Node2**
`python node.py Alice c PKI`

Terminal 4. Run malicious client: goto **gen-py/Node3**
`python node.py Mallory m PKI`

In order to see the outcome of verification, check the o/p on server's bash (i.e. Terminal 2).
