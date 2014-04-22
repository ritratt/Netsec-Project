import lib
import urllib2
import json
import use_certificate

def buildurl(h):
	base_url = 'http://blockchain.info/rawtx/'
	url = base_url + h
	return url

def getResp(url):
	resp = json.loads(urllib2.urlopen(url).read())
	return resp

def parseAddr(resp):
	from_address = resp['inputs'][0]['prev_out']['addr']
	to_address = resp['out'][0]['addr']

	return from_address, to_address

def provisionalCert():
	h = '458e46e2d7acffab6abc58acd7d34708fb57777a42492173569da24dfcbeb2c7'
	url = buildurl(h)
	resp = getResp(url)
	from_address, to_address = parseAddr(resp)

	pubkey = ''
	pseudonym = ''

	certificate = [h, pubkey, to_address, pseudonym, from_address]
	return certificate

CA_Addr = '17ykuwPtsVSofWJ6RpDVneVh2swocfENB8'
#Valid Certificate
print 'Generating test certificate.'
cert = provisionalCert()
print 'Test certificate generated successfully. Now checking if it is valid.'
use_certificate.use_certificate('', cert[2], '', CA_Addr)

#Manhandle the certificate retrieved above and check its validity
print 'Now manhandling the certificate above and checking if it is valid.'
cert[2] = 'randomaddressthatshouldnotwork'
use_certificate.use_certificate('', cert[2], '', CA_Addr)

#Test a certificate that does not exist.
CA_Addr = '12qLSoBaB5YzDxyoATinKofsUoGKvhJW6V'
print 'Now testing with a non-existent certificate/public key.'
cert = provisionalCert()
use_certificate.use_certificate('', cert[2], '', CA_Addr)
