#!/usr/bin/python

from sys import argv,path
from os import getcwd
path.append('/'.join(getcwd().split('/')[:-1]))

from service import RPCClientServer,NodeChatter
from service.ttypes import *
from service.constants import *
from OpenSSL import crypto
from thrift import Thrift
from thrift.server import TServer
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from os.path import isfile


def create_self_signed_cert(y):

    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 1024)

    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "GA"
    cert.get_subject().L = "ATL"
    cert.get_subject().O = "blah"
    cert.get_subject().OU = "blah"
    cert.get_subject().CN = y
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(5*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha1')

    open("%s.pem"%y, "wt").write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

class NodeHandler:
	def __init__(self):
		pass

	def verify(self,a):
		from os import system
		print '------------------------------------------------------'
		open("temp.pem", "wt").write(a)
		tempCert=crypto.load_certificate(crypto.FILETYPE_PEM,open('temp.pem','rb').read())
		system('mv temp.pem %s.pem'%tempCert.get_subject().commonName)
		print "Received client's cert"
		system('openssl verify -verbose -CAfile CA_cert.pem %s.pem'%tempCert.get_subject().commonName)
		system('rm %s.pem'%tempCert.get_subject().commonName)
		print '------------------------------------------------------','\n'

if __name__=='__main__':
	nodeName=argv[1]
	if not isfile("%s.pem"%nodeName) and argv[2] in ['s','c']:
		try:
			transport = TSocket.TSocket('localhost', 30303)
			transport = TTransport.TBufferedTransport(transport)
			protocol = TBinaryProtocol.TBinaryProtocol(transport)
			client = RPCClientServer.Client(protocol)
			
			transport.open()
			
			if argv[2] in ['s','c']:
				client.receiveReq(nodeName)
				print "Node receiving its certificate from CA."
				msg = client.sendCert()
				open("%s.pem"%nodeName, "wt").write(msg)
			
			if argv[2]=='s':
				print "Node receiving CA's certificate."
				msg = client.receiveCACert()
				open("CA_cert.pem", "wt").write(msg)
			
			transport.close()

		except Thrift.TException, tx:
			print "%s"%(tx.message)
	
	if argv[2]=='c':
		transport = TSocket.TSocket('localhost', 30305)
		transport = TTransport.TBufferedTransport(transport)
		protocol = TBinaryProtocol.TBinaryProtocol(transport)
		client = NodeChatter.Client(protocol)
		
		print "Starting node as client....."
		transport.open()
		client.verify(open("%s.pem"%nodeName).read())
		transport.close()
	
	elif argv[2]=='s':
		from os import system
		handler = NodeHandler()
		processor = NodeChatter.Processor(handler)
		transport = TSocket.TServerSocket(port=30305)
		tfactory = TTransport.TBufferedTransportFactory()
		pfactory = TBinaryProtocol.TBinaryProtocolFactory()
		 
		server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)
		 
		print "Starting node as server....."
		server.serve()
		print "done!"

	elif argv[2]=='m':
		transport = TSocket.TSocket('localhost', 30305)
		transport = TTransport.TBufferedTransport(transport)
		protocol = TBinaryProtocol.TBinaryProtocol(transport)
		client = NodeChatter.Client(protocol)
		create_self_signed_cert(nodeName)
		print "Starting node as malicious client....."
		transport.open()
		client.verify(open("%s.pem"%nodeName).read())
		transport.close()

	else:
		print "Invalid args!"
