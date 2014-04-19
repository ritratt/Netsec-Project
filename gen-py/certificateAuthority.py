#!/usr/bin/python
 
from service import RPCClientServer
from service.ttypes import *
from OpenSSL import crypto
from os.path import isfile
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer
from random import randint
 
def create_CA_cert():
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 1024)

    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "GA"
    cert.get_subject().L = "ATL"
    cert.get_subject().O = "blah"
    cert.get_subject().OU = "blah"
    cert.get_subject().CN = "CA"
    cert.set_serial_number(randint(1,5000))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(5*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha1')

    open("CA.pem", "wt").write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open("CA_pri.pem", "wt").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    return cert


class CAHandler:
    def __init__(self):
        self.__CAcert=None
        self.__CAkey=None
        self.__entity=None
        if not isfile("CA.pem"):
            self.__CAcert=create_CA_cert()
        else:
            self.__CAcert=crypto.load_certificate(crypto.FILETYPE_PEM,open('CA.pem','rb').read())
        self.__CAkey=crypto.load_privatekey(crypto.FILETYPE_PEM,open('CA_pri.pem','rb').read())

    def sendCert(self):

        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 1024)

        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "GA"
        cert.get_subject().L = "ATL"
        cert.get_subject().O = "blah"
        cert.get_subject().OU = "blah"
        cert.get_subject().CN = self.__entity
        cert.set_serial_number(randint(1,5000))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*24*60*60)
        cert.set_issuer(self.__CAcert.get_subject())
        cert.set_pubkey(k)
        cert.sign(self.__CAkey, 'sha1')
        return crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

    def receiveReq(self,a):
        print "Received certificate request for %s."%a
        self.__entity=a

    def receiveCACert(self):
        return crypto.dump_certificate(crypto.FILETYPE_PEM,self.__CAcert)

handler = CAHandler()
processor = RPCClientServer.Processor(handler)
transport = TSocket.TServerSocket(port=30303)
tfactory = TTransport.TBufferedTransportFactory()
pfactory = TBinaryProtocol.TBinaryProtocolFactory()

server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)

print "Starting CA server....."
server.serve()
