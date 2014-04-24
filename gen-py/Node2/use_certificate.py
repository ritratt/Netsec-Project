import hashlib
import urllib2
import base64
import lib

'''Client uses this function to verify the certificate presented by a server'''
def use_certificate(pubkey, address, pseudonym, CA_Addr):
	
	#Calculate transaction amount from the pseudonym
	h = hashlib.sha512()
	h.update(pseudonym)
	btc_amount = h.hexdigest()
	
	#Verify if the public key and address pair is valid. Abort if not.
	#if(!(lib.verify(pubkey, address))):
	#	print 'Public key and address pair do not match.'
	#	return -1

	#Set the CA_Addr as per requirement. Can be made to read from an input file or console input etc. Blank for now.
	#CA_Addr = '17ykuwPtsVSofWJ6RpDVneVh2swocfENB8'

	#Check if a certificate was ever issued. Abort if not.
	if(not (lib.absence(pseudonym, CA_Addr))):

		print 'No certificate was ever issued to the server by the CA.'
		return -1

	#Retrieve the transaction id/hash from the blockchain with earliest time stamp that was issued to the 'address' parameter passed.
	id = lib.retrieve(btc_amount, CA_Addr, address)

	#Retrieve the address corresponding to the earliest certificate issued by the CA with amount = btc_amount
	address_toVerify = lib.currency(pseudonym, CA_Addr)

	if address_toVerify == address:
		print 'Certificate valid.'
		return True
	else:
		print 'Certificate invalid.'
		return False
	
