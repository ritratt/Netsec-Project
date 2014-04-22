import lib
import urllib2

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

	certificate = [h, pubkey, to_address, pseudonym, from_address]
