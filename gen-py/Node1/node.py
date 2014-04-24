#!/usr/bin/python

from sys import argv,path
from os import getcwd
path.append('/'.join(getcwd().split('/')[:-1]))

from service import RPCClientServer,NodeChatter
from service.ttypes import *
from service.constants import *
from thrift import Thrift
from thrift.server import TServer
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from os.path import isfile
from random import randint
from OpenSSL import crypto
import struct
import sys

import BitcoinTest

# \file node.py

# \brief - Create Self Signed Certificate
# \param y - Common Name
# \returns none
def create_self_signed_cert(y):
    '''Create Self Signed Certificate'''	

    from OpenSSL import crypto

    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 1024)

    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "GA"
    cert.get_subject().L = "ATL"
    cert.get_subject().O = "org"
    cert.get_subject().OU = "organizationUnit"
    cert.get_subject().CN = y
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(5*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha1')

    open("%s.pem"%y, "wt").write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

# \brief - Create Merkle Tree Leaf
# \param - timestamp - Timestamp
# \param - x509_cert_bytes - X509 Certificate Bytes
def createMerkleTreeLeaf(timestamp, x509_cert_bytes):

	from ct.client import tls_message
	from ct.proto import client_pb2
	from ct.proto import ct_pb2

	leaf = client_pb2.MerkleTreeLeaf()
	leaf.version = client_pb2.V1
	leaf.leaf_type = client_pb2.TIMESTAMPED_ENTRY
	leaf.timestamped_entry.timestamp = timestamp
	leaf.timestamped_entry.entry_type = client_pb2.X509_ENTRY
	leaf.timestamped_entry.asn1_cert = x509_cert_bytes

	return tls_message.encode(leaf)

# \brief - Retrieve Timestamp from Map
# \param - commonName
# \returns - SCT timestamp'''
def retrieveTimestampFromMap(commonName):
    timestampMap = {'www.bankofamerica.com': 1393154605606}
    timestamp = 0
    
    try:	
        timestamp = timestampMap[commonName]
    except KeyError:
        timestamp = 0
        
    return timestamp

'''!@brief - Verify Certificate Presence in Google CT Log
    @param - Self
 @param - a - Certificate Raw Bytes
 @returns - none''' 
def verifyCertInGoogleCTLog(self,a):

	print '--------------------------------------------'
	from ct.client import log_client
	from ct.crypto import cert
	from ct.crypto import merkle
	from OpenSSL import crypto

	
	open("temp.pem", "wt").write(a)
	tempCert=crypto.load_certificate(crypto.FILETYPE_PEM, open('temp.pem', 'rb').read())

	timestamp = retrieveTimestampFromMap(tempCert.get_subject().commonName)
	
	'''if timestamp == 0:
		print 'SCT Timestamp not specified in Certificate'
		print '-------------------------------------------'
		return
	'''

	cert_to_lookup = cert.Certificate.from_pem_file('temp.pem')
    	constructed_leaf = createMerkleTreeLeaf(timestamp,cert_to_lookup.to_der())
    	leaf_hash = merkle.TreeHasher().hash_leaf(constructed_leaf)

        verificationserverurl="ct.googleapis.com/pilot"
        revocationserverurl="ct.googleapis.com/aviator"
	
        verificationclient = log_client.LogClient(verificationserverurl)
	revocationclient = log_client.LogClient(revocationserverurl)

	revocation_sth = revocationclient.get_sth()
	
	try:
		proof_from_hash = revocationclient.get_proof_by_hash(leaf_hash, revocation_sth.tree_size)
		print "Certificate has been revoked"
		return
	except Exception:
		print "Certificate is not revoked. Checking validity"
        
	verification_sth = verificationclient.get_sth()
         
    	#If exception thrown return false, else return true
    	try:
        	proof_from_hash = verificationclient.get_proof_by_hash(leaf_hash, verification_sth.tree_size)
                print "Certificate verified in the Google CT Log"
    	except Exception as e:
                print "Certificate not verified"
	print '----------------------------------------------------'
	
class NodeHandler:
	def __init__(self):
		pass

	def verify(self,a,model):

		'''If Verification Model is PKI, Verify the Certificate Chain'''
		if model == 'PKI':
			from os import system
			print '------------------------------------------------------'
			open("temp.pem", "wt").write(a)
			tempCert=crypto.load_certificate(crypto.FILETYPE_PEM,open('temp.pem','rb').read())
			system('mv temp.pem %s.pem'%tempCert.get_subject().commonName)
			print "Received client's cert"
			system('openssl verify -verbose -CAfile CA_cert.pem %s.pem'%tempCert.get_subject().commonName)
			system('rm %s.pem'%tempCert.get_subject().commonName)
			print '------------------------------------------------------','\n'

		elif model == 'GoogleCT':
			verifyCertInGoogleCTLog(self,a)

		elif model == 'BitcoinCT':
			BitcoinTest.main()

    		
	
if __name__=='__main__':

    nodeName=argv[1]
    
    if argv[2]=='s' and len(argv)==3:
        '''
        In server mode, the node primarily checks if it has its certificate and the certificate of CA. If either of the certificate(s)
        is missing, it makes RPC calls to the CA to get required certificates. CA's certificate is required by the server node in 
        order to verfiy a client node (i.e. in PKI model). The output of verification is printed on the bash where server node is 
        live.
        '''
        
        if not isfile("CA_cert.pem") or not isfile("%s.pem"%nodeName):
            try:
                transport = TSocket.TSocket('localhost', 30303)
                transport = TTransport.TBufferedTransport(transport)
                protocol = TBinaryProtocol.TBinaryProtocol(transport)
                client = RPCClientServer.Client(protocol)
                    
                transport.open()
                
                if not isfile("CA_cert.pem"):
                    print "Node receiving CA's certificate."
                    msg = client.receiveCACert()
                    open("CA_cert.pem", "wt").write(msg)
                
                if not isfile("%s.pem"%nodeName):
                    client.receiveReq(nodeName)
                    print "Node receiving its certificate from CA."
                    msg = client.sendCert()
                    open("%s.pem"%nodeName, "wt").write(msg)

                transport.close()

            except Thrift.TException, tx:
                print "%s"%(tx.message)

        handler = NodeHandler()
        processor = NodeChatter.Processor(handler)
        transport = TSocket.TServerSocket(port=30305)
        tfactory = TTransport.TBufferedTransportFactory()
        pfactory = TBinaryProtocol.TBinaryProtocolFactory()
         
        server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)
         
        print "Starting node as server....."
        server.serve()
        
    elif argv[2]=='c' and len(argv)==4:
        '''
        In client mode, the node checks if it has a valid certificate (i.e. one issued by the CA). If not, it makes an RPC call and gets
        its certificate. Post which, it sends its certificate to the server node for verification (via a RPC call).
        '''
        verificationModel=argv[3]
        if not isfile("%s.pem"%nodeName):
            try:
                transport = TSocket.TSocket('localhost', 30303)
                transport = TTransport.TBufferedTransport(transport)
                protocol = TBinaryProtocol.TBinaryProtocol(transport)
                client = RPCClientServer.Client(protocol)
                    
                transport.open()
                client.receiveReq(nodeName)
                print "Node receiving its certificate from CA."
                msg = client.sendCert()
                open("%s.pem"%nodeName, "wt").write(msg)
                transport.close()

            except Thrift.TException, tx:
                print "%s"%(tx.message)

        try:
            transport = TSocket.TSocket('localhost', 30305)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = NodeChatter.Client(protocol)

            print "Starting node as client....."
            transport.open()
            client.verify(open("%s.pem"%nodeName).read(),verificationModel)
            transport.close()

        except Thrift.TException, tx:
                print "%s"%(tx.message)

    elif argv[2]=='m' and len(argv)==4:
        '''
        In (malicious) client mode, the node checks if it has a certificate. If not, it issues itself a certificate
        and tries to authenticate itself to the server node. In order to verify itself, it makes a RPC call -
        presenting its certificate to the server node.
        '''
        verificationModel=argv[3]
        try:
            transport = TSocket.TSocket('localhost', 30305)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = NodeChatter.Client(protocol)
            if not isfile("%s.pem"%nodeName):
                create_self_signed_cert(nodeName)
            print "Starting node as malicious client....."
            transport.open()
            client.verify(open("%s.pem"%nodeName).read(),verificationModel)
            transport.close()

        except Thrift.TException, tx:
                print "%s"%(tx.message)
    else:
        print "Invalid number/type of option(s) passed!"

