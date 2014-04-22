import urllib2
import hashlib
import json
import util
import addrgen
import base64
import coinkit

#A function that tells you if the CA ever issued a certificate to entity with pseudonym.
def absence(pseudonym, CA_addr):
	
	#Calculate the transaction amount from the pseudonym
	h = hashlib.sha512()
	h.update(pseudonym)
	hash = h.hexdigest()

	#Slash the hash (and consequently the amount) to 10 digits so that the transactions are affordable.
	hash = (int(hash[-20:], 16))/10**10 

	#Retrieve data from the blockchain for the CA's bitcoin address and convert it into python parseable format
	url = 'http://blockchain.info/address/' + CA_addr + '?format=json'
	raw_response = urllib2.urlopen(url).read()
	json_response = json.loads(raw_response)

	txs = json_response['txs']
	for tx in txs:
		#This line extracts the address and values from the response
		if tx['inputs'][0]['prev_out']['addr'] == CA_addr:
			print 'Key Found!'
			return True
	print 'No Key found!'
	#txns = json_response['txs'][0]['inputs'][0]['prev_out']['addr']
	return False
	

#Returns a set of transaction ids from CA to Client with given btc amount.
def retrieve(btc_amount, CA_Addr, Client_addr):

	#Retrieve data from blockchain. Convert it.
	ids = []
	url = 'http://blockchain.info/address/' + CA_Addr + '?format=json'
        raw_response = urllib2.urlopen(url).read()
        json_response = json.loads(raw_response)

	txs = json_response['txs']
	for tx in txs:
		#Add the id/hash to the array if the transaction was made from the CA to the Client with the calculated transaction amount.
		if((tx['inputs'][0]['prev_out']['addr'] == CA_Addr) and (tx['inputs'][0]['prev_out'] == Client_addr)):
			ids.append(tx['hash'])
	return ids

#A function that validates if the ECC Public Key and Bitcoin Address are a valid pair.
def validate(version, pubkey, addr_input):
	return True
	
	
#Function that returns the first public key out of the multiple keys issued by CA to Client.
def currency(pseudonym, CA_Addr):

	#Calculate the transaction amount
	h = hashlib.sha512()
	h.update(pseudonym)
	btc_amount = h.hexdigest()

	#Slash the hash (and consequently the amount) to 10 digits so that the transactions are affordable.
	btc_amount = (int(btc_amount[-20:], 16))/10**10

	#Retrieve data from blockchain
	url = 'http://blockchain.info/address/' + CA_Addr + '?format=json'
        raw_response = urllib2.urlopen(url).read()
        json_response = json.loads(raw_response)

        txs = json_response['txs']
	earliest = txs[0]['time']
	index = txs[0]['tx_index']
        for tx in txs:
                if((tx['inputs'][0]['prev_out']['addr'] == CA_Addr) and tx['time'] < earliest):
			print 'Earliest Key found. Replacing current key.'
			earliest = tx['time']
			index = tx['tx_index']
	url_txindex = 'http://blockchain.info/tx-index/' + str(index) + '?format=json'
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
	
pubkey = '0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798'
pubkey_uncompressed = '0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'

addr = '1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm'
validate(0, pubkey_uncompressed, addr)
