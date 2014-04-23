import urllib2
import lib
import hashlib
import json
import addrgen

#Used by CA to verify stuff and issue a certificate to the client
def issue(pubkey, secretkey, from_address, pseudonym, to_address):

	#Calculate the transaction amount by hashing the pseudonym.
	h = hashlib.sha512()
	h.update(pseudonym)
	btc_amount = h.hexdigest()

	#Abort if the address, pubkey pair do not match.
	if(!(lib.verify(pubkey, address)):
		print 'Public Key and Address pair do not match.'
		return -1
	
	tx_id = lib.insert(from_address, to_address, btc_amount, privateke, privatekey)
	
	#Signature is 'default' for now since we do not have the capabilities of a CA.
	signature = 'default'

	#Create the certificate as an amalgamation of all the important stuff and return it to the callee.
	certificate = [tx_id, pubkey, address, pseudonym, signature]
	return certificate


