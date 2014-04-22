import urllib2
import hashlib

def certcheck(publickey, pseudonym, address):
  if(!validate(pulickey, address):
    print 'Public key and Bitcoin address do not match. Certificate check failed. Aborting.'
    return
    
  amount = hashlib.sha512()
  amount.update(pseudonym)
  
  ids = retrieve(CA_Addr, pseudonym)
  if ids == null:
    print 'No transactions on blockchain found. Aborting.'
    return
    
    for id in ids:
      if id['tx_index'] < least_index:
        least_index = id['tx_index']
        
    address_v = get_addr(least_index)
    if address_v == address:
      print 'Certificate verification succeeded!'
      return True
    else:
      print 'Certificate verification failed!'
      return False

  
