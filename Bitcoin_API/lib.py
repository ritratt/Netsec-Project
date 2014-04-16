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
		if tx['inputs'][0]['prev_out']['addr'] == CA_addr and tx['inputs'][0]['prev_out']['value'] == hash:
			print 'Key Found!'
			return
	print 'No Key found!'
	txns = json_response['txs'][0]['inputs'][0]['prev_out']['addr']
	

#Returns a set of transaction ids from CA to Client with given btc amount.
def retrieve(btc_amount, CA_Addr, Client_addr):
	ids = []
	url = 'http://blockchain.info/address/' + CA_addr + '?format=json'
        raw_response = urllib2.urlopen(url).read()
        json_response = json.loads(raw_response)

	txs = json_response['txs']
	for tx in txs:
		if((tx['inputs'][0]['prev_out']['addr'] == CA_Addr) and (tx['inputs'][0]['out'] == Client_addr) and (tx['inputs'][0]['prev_out']['value'] == btc_amount)):
			ids.append(tx['hash']
	return ids

#A function that validates if the ECC Public Key and Bitcoin Address are a valid pair.
def validate(version = 0, pubkey, addr_input):
    if not len(pubkey) == 44:
        print 'Public key input is not recognized. Please try again with the correct public key.'
        return
    pubkey = base64.b64decode(pubkey)
    hash160 = util.rhash(pubkey)
    addr = base58_check_encode(hash160,version)
    if addr == addr_input:
        print 'Given public key is valid for the given address!'
	return True
    else:
        print 'Given public key and address do not match!'
	return False

#Function that returns the first public key out of the multiple keys issued by CA to Client.
def currency(pseudonym, CA_Addr):
	h = md5.sha512()
	h.update(pseudonym)
	btc_amount = h
	
	url = 'http://blockchain.info/address/' + CA_addr + '?format=json'
        raw_response = urllib2.urlopen(url).read()
        json_response = json.loads(raw_response)

        txs = json_response['txs']
	earliest = txs[0]['time']
        for tx in txs:
                if(tx['inputs'][0]['prev_out']['addr'] == CA_Addr) and tx['inputs'][0]['prev_out']['value'] == btc_amount and tx['time'] < earliest):
			earliest = tx['time']
			index = tx['tx_index']
	url_txindex = 'http://blockchain.info/tx-index/' + index + '?format=json'
	resp = json.loads(urllib2.urlopen(url_txindex).read())
	
	first_addr = resp['out'][0]['addr']
	return first_addr
	

