#!/usr/bin/env python

#author - Akshata
import struct
import sys
import json
import base64
import requests
from ct.crypto import cert
from requests import Session, Request

#Function: Adds Certificate to Chain
#Param: URL - url
#Param: Certificate Array - certificateArray - With end-entity certificate at 0th index and root-certificate at the end
#Returns: SCT Timestamp for the Log Entry
def addChain(url, certificateArray):

	base64CertArray = []	

        #Form the certificate chain post parameter
        for certificateFile in certArray:	   
            cert_to_lookup = cert.Certificate.from_pem_file(certificateFile)
            certstring = base64.b64encode(cert_to_lookup.to_der())
            base64CertArray.append(certstring)
            
        #Make a JSON post request
        url = url + "ct/v1/add-chain"
        data1 = json.dumps({'chain':base64CertArray}) 
        headers = {'content-type': 'application/json'}
        response = requests.post(url, data=data1, headers=headers)

        timestamp = -1
        
        #Return SCT timestamp
        if response.status_code == requests.codes.ok:
            decoded_data = json.loads(response.text)
            timestamp =  decoded_data["timestamp"]
        else: 
            print "Error", response.status_code
            print response.text
            
        return timestamp    


#Function: Main()
if __name__ == '__main__':
    
    if len(sys.argv) < 3:
        print "Usage: %s <comma-separated-list-of-certificate-chain-with-end-entity-at-start-and-root-at-end> <log-server-url>"
        exit()
    certList = sys.argv[1]
    ctserverurl = sys.argv[2]
    certArray = certList.split(',')
    timestamp = addChain(ctserverurl, certArray)
    print timestamp
	

#usage: python add-chain.py boa.pem,oneICA.pem,root.pem http://ct.googleapis.com/pilot/
