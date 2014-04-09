import urllib2
import hashlib
import json

def absence(pseudonym, CA_addr):
	h = hashlib.sha512()
	h.update(pseudonym)
	hash = h.hexdigest()

	url = 'http://blockchain.info/address/' + CA_addr + '?format=json'
	raw_response = urllib2.urlopen(url).read()
	json_response = json.loads(raw_response)

	print 'JSON response successfully parsed.'

	txs = json_response['txs']
	for tx in txs:
		if tx['inputs'][0]['prev_out']['addr'] == CA_addr and tx['inputs'][0] == hash:
			print 'Key Found!'
			return
	print 'No Key found!'
	txns = json_response['txs'][0]['inputs'][0]['prev_out']['addr']
	
