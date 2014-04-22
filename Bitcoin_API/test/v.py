import hashlib
import base64

def rhash(s):
    h1 = hashlib.new('ripemd160')
    h1.update(hashlib.sha256(s).digest())
    return h1.digest()

def validate_pubkey(version = 0):
    pubkey = raw_input("Enter the Base64 encoded public key:\n>")
    if not len(pubkey) == 44:
        print 'Public key input is not recognized. Please try again with the correct public key.'
        return
    addr_input = raw_input("Enter the bitcoin address for which you need to validate the public key:\n>")
    pubkey = base64.b64decode(pubkey)
    hash160 = rhash(pubkey)
    addr = base58_check_encode(hash160,version)
    if addr == addr_input:
        print 'Given public key is valid for the given address!'
    else:
        print 'Given public key and address do not match!'

