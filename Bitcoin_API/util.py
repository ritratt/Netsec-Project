'''Utility functions that we might need to use are all in here.'''

import hashlib

#Utility function for finding ripemd160 hash.
def rhash(s):
    h1 = hashlib.new('ripemd160')
    h1.update(hashlib.sha256(s).digest())
    return h1.digest()
