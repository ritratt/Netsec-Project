##README:

This suite was developed to compare the performance of the Bitcoin Blockchain Certificate Transparency library with the existing models of PKI and Google Certificate Transparency. We simulate the verification of a legitimate/fraudulent certificate in each of the models. The setup consists of 4 entities - the Certificate Authority, a certificate validating server, a legitimate client and a malicious client.

###PKI Simulation
Using this suite, it is possible to simulate public key infrastructure - commonly employed for distributing certificates. In the current arrangement, there are two key entities - certificate authority (`CA`) and `node` (which can behave as either a server or client - depending on the arguments passed via command-line). The `CA` is centralized in nature - only one `CA` exists for the entire setup. Any node which intends to have a secure communication with its peer, needs to get a certificate issued by the `CA`. In the current setup, the `server` node is responsible for verifying the certificates presented by `client`(s). The server node verifies the certificate using `CA`'s certificate as reference - should the certificate be issued by the centralized `CA`, the certificate will be verified and the server node's bash will output an appropriate message. If the certificate was not issued by the centralized `CA` (or is invalid), error message would be output to server's bash. All the communication among different nodes and the `CA` takes place via Remote Procedure Calls (RPC) - facilitated using Apache Thrift. 

####Dependencies:
1. pyOpenSSL - https://pypi.python.org/pypi/pyOpenSSL
2. Thrift (Py version) - https://pypi.python.org/pypi/thrift 
(install post-extraction)

####Runtime Environment: 
Any flavor of **LINUX**

####How to run: (change your cwd to gen-py)
Change your permissions to root using sudo.

Terminal 1. You need to have the CA live, primarily: 

`python certificateAuthority.py`

Terminal 2. Run server: goto **gen-py/Node1** 

`python node.py Bob s`

Terminal 3. Run legit client: goto **gen-py/Node2** 

`python node.py Alice c PKI`

Terminal 4. Run malicious client: goto **gen-py/Node3** 

`python node.py Mallory m PKI`

In order to see the outcome of verification, check the o/p on server's bash (i.e. Terminal 2).

###Google CT Simulation
Using this suite, it is possible to simulate certificate verification using the Google Certificate Transparency concept. The client server model is identical to the PKI model. However, it validates if the certificate is present in the Google Certificate Transparency log. Currently, we have inserted the Bank of America certificate in the Google CT log, so for a legitimate client - we validate the presence of the Bank of America certificate in the log. In addition, the certificate is checked for its presence in the revocation log (mentioned in the design document/poster). 

###Setup:
1. Install the dependencies from the dependency list
1. Extract the bundled certificate-transparency.zip folder
1. Set the LD_library_path to LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib/
1. Verify if the following line in the certificate-transparency/src/python Makefile points to the directories where the libprotoc.so libraries were installed.

        protoc $^ -I/usr/include/ -I. -I/usr/local/include --python_out=.
1. In the certificate-transparency/src/python folder, run 'make'
1. In case you see a 'cannot import name enum_type_wrapper' error, navigate to the protobuf-2.5.0/python folder. Run the following commands.

        python setup.py build
        python setup.py install
1. Run 'make' once more

###Dependencies:
1. pip install simplejson
1. pip install python-gflags
1. pip install requests
1. pip install ecdsa
1. pip install mock
1. easy_install 'https://google-visualization-python.googlecode.com/files/gviz_api_py-1.8.2.tar.gz'
1. apt-get install build-essential python-dev
1. pip install twisted
1. Download the protoc 2.5.0 zip from https://code.google.com/p/protobuf/ . Install using the following steps

        $ sudo ./configure --prefix=/usr
        $ sudo make
        $ sudo make check
        $ sudo make install
        $ protoc --version

###How to run(change cwd to gen-py)
1. Change your permissions to root using sudo
    `export PYTHONPATH=$PYTHONPATH:/path-to-/installation-dir/certificate-transparency/src/python-folder`

Terminal 1. You need to have the CA live, primarily:

`python certificateAuthority.py`

Terminal 2. Run server: goto **gen-py/Node1**

`python node.py Bob s`

Terminal 3. Run legit client: goto **gen-py/Node2**

`python node.py www.bankofamerica.com c GoogleCT`

Terminal 4. Run malicious client: goto **gen-py/Node3**

`python node.py Mallory m GoogleCT`

In order to see the outcome of verification, check the o/p on server's bash (i.e. Terminal 2).

###Additional Google CT Utilities
The setup instructions is the same as listed in the previous section.
Navigate to the Google_CT_API folder. Change permissions to root. Run the following command.

    `export PYTHONPATH=$PYTHONPATH:/path-to-/installation-dir/certificate-transparency/src/python-folder` 

1. Addition of a certificate to the certificate transparency log

    The sample certificates have already been placed in the folder. If you wish to add your own trusted certificate to the log, run the following command, replacing the certificate file paths with your own. The order of the certificate PEM files from left to right, must be listed as the end-entity certificate at the beginning, the ICA chain certificate and the root certificate in the end. The SCT timestamp is returned to you as a result.
    
        `python add-chain.py boa.pem,oneICA.pem,root.pem http://ct.googleapis.com/pilot/`
1. Verification of the existence of a certificate in the certificate transparency log

    The sample Bank of America certificate has already been placed in the folder. Run the following command. A 'Certificate is in Log' message should be output if the certificate was found in the log
    
        python verify_certificate.py --certificate boa.pem --timestamp 1393154605606
    
