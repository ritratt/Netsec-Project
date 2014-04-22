import urllib2
import hashlib
import json
import util
import addrgen
import base64


#A function that tells you if the CA ever issued a certificate to entity with pseudonym.
def absence(pseudonym, CA_addr):
	
	#Calculate the transaction amount from the pseudonym
	h = hashlib.sha512()
	h.update(pseudonym)
	hash = h.hexdigest()

	#Retrieve data from the blockchain for the CA's bitcoin address and convert it into python parseable format
	url = 'http://blockchain.info/address/' + CA_addr + '?format=json'
	raw_response = urllib2.urlopen(url).read()
	json_response = json.loads(raw_response)

	txs = json_response['txs']
	for tx in txs:
		#This line extracts the address and values from the response
		if tx['inputs'][0]['prev_out']['addr'] == CA_addr and tx['inputs'][0]['prev_out']['value'] == hash:
			print 'Key Found!'
			return True
	print 'No Key found!'
	txns = json_response['txs'][0]['inputs'][0]['prev_out']['addr']
	return False
	

#Returns a set of transaction ids from CA to Client with given btc amount.
def retrieve(btc_amount, CA_Addr, Client_addr):

	#Retrieve data from blockchain. Convert it.
	ids = []
	url = 'http://blockchain.info/address/' + CA_addr + '?format=json'
        raw_response = urllib2.urlopen(url).read()
        json_response = json.loads(raw_response)

	txs = json_response['txs']
	for tx in txs:
		#Add the id/hash to the array if the transaction was made from the CA to the Client with the calculated transaction amount.
		if((tx['inputs'][0]['prev_out']['addr'] == CA_Addr) and (tx['inputs'][0]['out'] == Client_addr) and (tx['inputs'][0]['prev_out']['value'] == btc_amount)):
			ids.append(tx['hash'])
	return ids

#A function that validates if the ECC Public Key and Bitcoin Address are a valid pair.
def validate(version, pubkey, addr_input):
	
	pubkey_decoded = addrgen.base58_check_decode(pubkey, 128 + 0)
	hash160 = util.rhash(pubkey_decoded)
	addr = addrgen.base58_check_encode(hash160,version)
	if addr == addr_input:
		print 'Given public key is valid for the given address!'
		return True
	else:
		print 'Given public key and address do not match!'
		return False

#Function that returns the first public key out of the multiple keys issued by CA to Client.
def currency(pseudonym, CA_Addr):

	#Calculate the transaction amount
	h = md5.sha512()
	h.update(pseudonym)
	btc_amount = h.hexdigest()
	
	url = 'http://blockchain.info/address/' + CA_addr + '?format=json'
        raw_response = urllib2.urlopen(url).read()
        json_response = json.loads(raw_response)

        txs = json_response['txs']
	earliest = txs[0]['time']
        for tx in txs:
                if((tx['inputs'][0]['prev_out']['addr'] == CA_Addr) and tx['inputs'][0]['prev_out']['value'] == btc_amount and tx['time'] < earliest):
			earliest = tx['time']
			index = tx['tx_index']
	url_txindex = 'http://blockchain.info/tx-index/' + index + '?format=json'
	resp = json.loads(urllib2.urlopen(url_txindex).read())
	
	first_addr = resp['out'][0]['addr']
	return first_addr
	
#Generates a Bitcoin ECC Public Key, Secret Key & Address. Not sure if the secret key should be generated and returned in plain sight like this.
def gen():

	eckey = addrgen.gen_eckey(compressed=True, version = 0)
	pubkey, secretkey, address = addrgen.get_addr(eckey, version = 0)
	return [pubkey, secretkey, address]

#Make a bitcoin transaction which inserts a key into the blockchain.
def insert(from_address, to_address, amount, privatekey):
	
	#Make blockchain API call to transfer transfer BTC from CA to Client.
	url = 'https://blockchain.info/merchant/' + privatekey + '/payment?to=' + address + '&amount=' + str(amount) + '&from=' + from_address + '&shared=false&e=$note'
	raw_response = urllib2.urlopen(url).read()
	json_response = json.loads(raw_response)

	#transaction hash is the id that we return to the user. Not sure if returning the transaction id or transaction hash is better.
	tx_id = json_response['tx_hash']
	return tx_id
	
