import urllib2
import hashlib
import json
import util

#A function that tells you if the CA ever issued a certificate to entity with pseudonym.
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
	

#A function that validates if the ECC Public Key and Bitcoin Address are a valid pair.
def validate(version = 0):
    pubkey = raw_input("Enter the Base64 encoded public key:\n>")
    if not len(pubkey) == 44:
        print 'Public key input is not recognized. Please try again with the correct public key.'
        return
    addr_input = raw_input("Enter the bitcoin address for which you need to validate the public key:\n>")
    pubkey = base64.b64decode(pubkey)
    hash160 = util.rhash(pubkey)
    addr = base58_check_encode(hash160,version)
    if addr == addr_input:
        print 'Given public key is valid for the given address!'
    else:
        print 'Given public key and address do not match!'

