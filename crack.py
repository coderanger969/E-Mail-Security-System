#!/usr/bin/python

import os
import sys
import urllib
import re
import subprocess
import random

# Weblink to obtain the list of all certificates.
webLink = "https://courses.ncsu.edu/csc574/lec/001/CertificateRepo"

# Gobal Variables
certificatesFileName = "certificateList.txt"
tempStorage = "tempStorage.txt"
certificatesLinksFileName = "globalCertificateLinks.txt"
localCertificates = {}
globalCertificatesLinks = {}
numberOfCertificates = 0

# CA details
caCert = "root-ca.crt"
SHA1ofCert = "EA:8A:F7:B7:4B:C7:E6:4B:59:E4:50:14:FA:88:D2:26:65:22:C4:23"

# For Random Passphrase
myStudentId = 62585
passPhrase = ""

# Sender Details
senderName = ""

# For formatting the message body
beginNote = "-----BEGIN CSC574 MESSAGE-----"
endNote = "-----END CSC574 MESSAGE-----"
forSignature = "forSignature.txt"
encForSignature = "forSignature.txt.sig"
myMailId = "vcheruk2@ncsu.edu"
sendTo = ""
messageFile = "message.txt"
encKey = "encKey.txt"
keyFile = "key.txt"
encBodyFile = "encBody.txt"
receivedMsgFile = "decryptedOutput.txt"

# Private Key Variable
privateKey = "rmPrivateKey.pem"

# Function used to initialize the program
def initialize():
	getCertificateListFromWebsite()
	validateCA()
	updateLocalDB()

# Function used to update the local database
def updateLocalDB():
	cmd = "ls | grep .pem"
	consoleOutput = os.popen(cmd).readlines()
	for i in xrange(0,len(consoleOutput)):
		#if consoleOutput[i][:-5]+".pem" != privateKey:
		localCertificates.update({consoleOutput[i][:-5]: consoleOutput[i][:-5]+".pem" })

	del localCertificates["rmPrivateKey"]

	temp = localCertificates.keys()
	fo = open("localCertificates.txt","w+")
	for i in xrange(0,len(consoleOutput)-1):
		#if temp[i]+".pem" is not privateKey:
		tempString = "{0} {1}\n".format(temp[i], temp[i]+".pem")
		fo.write(tempString)
	fo.close()

# Function which deletes all the metafiles created during the program.
def deleteMetaFiles():
	try:
		cmd = "rm -rf "
		os.system(cmd+forSignature)
		os.system(cmd+encForSignature)
		#os.system(cmd+keyFile)
		os.system(cmd+encKey)
		os.system(cmd+"body.txt")
		os.system(cmd+"encBody.txt")
		os.system(cmd+sendTo+"Public.pem")
		cmd = ""
	except Exception, e:
		print "Error while deleting the meta files."
		print e

# Form's the message and stores in message.txt
def msgMaker(sid,body,sign):
	try:
		os.system("rm -rf "+messageFile)	# remove previous message file (if any)
	
		header = "from: "+myMailId+", to: "+sendTo

		fo = open(messageFile,"w+")
		fo.write(header+"\n")
		fo.write(beginNote+"\n")
		fo.write(sid+"\n")
		fo.write('\n')
		fo.write(body+"\n")
		fo.write(sign+'\n')
		fo.write(endNote)

		fo.close()
		return 1
	except Exception, e:
		print "Error while formulating the message."
		print e
		return -1

# Function to get the links to certificates from website
def getCertificateListFromWebsite():
	global globalCertificatesLinks,numberOfCertificates
	try:
		fo1 = urllib.urlopen(webLink)

		try:
			fo2 = open("globalCertificateLinks.txt","w+")
		except Exception, e:
			print "Unable to open globalCertificateLinks.txt."
			print e

		to = open(tempStorage,"w+")
		to.write(fo1.read())
		to.close()
		fo1.close()

		# Read the data from disk to local variable
		try:
			numberOfCertificates = sum(1 for line in open(tempStorage))
			to = open(tempStorage,"r+")
			for i in xrange (0,numberOfCertificates):
				line = to.readline()
				if ',' in line:
					temp = line.split(',')
					globalCertificatesLinks.update({temp[0]:temp[1]})
				else:
					temp = line.split()
					globalCertificatesLinks.update({temp[0]:temp[1]})
			to.close()
		except Exception, e:
			print "Error while reading the data from disk to local Variable."
			print e		

		# Write the data from disk to local variable
		#writeToDisk("latestCertificates.txt","w+")
		try:
			temp = list(globalCertificatesLinks.keys())
			#print "number of keys = ",len(temp)
			
			for i in xrange(len(temp)):
				tempString = "{0} {1}".format(temp[i], globalCertificatesLinks[temp[i]])
				fo2.write(tempString)
				#print i,temp[i]
			fo2.close()
		except Exception, e:
			print "Error while writing in memory data to disk file."
			print e

		# Delete the temporary storage text file
		delTempStorage = "rm -rf {0}".format(tempStorage)
		os.system(delTempStorage)
		return 1
	except Exception, e:
		print e
		print "Unable to open "+webLink+". Please sign-in to your myPack account or check the link provided."
		return -1

# Checks if the senderId is valid or not and returns the name of the PEM file if valid else returns -1
def validateSenderId(senderId):
	global localCertificates
	try:
		link = globalCertificatesLinks[senderId]
		
		# Check if the PEM file is already present, if it is then return it otherwise retrieve it and add it.
		if(senderId in localCertificates.keys()):
			print senderId, "is already present in the local DateBase"
			return senderId+".pem"

		os.system("rm -rf "+senderId+".pem")
		urllib.urlretrieve(link,senderId+".pem")
		localCertificates.update({senderId : senderId+".pem"})
		return senderId+".pem"
	except Exception, e:
		print "SenderId",e,"does not exists. Be careful."
		return -1

# Checks if the CA is valid or not.
def validateCA():
	try:
		cmd = "openssl x509 -noout -in "+caCert+" -fingerprint"
		#consoleOutput = subprocess.popen(cmd, stdout=subprocess.PIPE).communicate()[0]
		consoleOutput = os.popen(cmd).readlines()
		consoleOutputasStr = ''.join(consoleOutput)
		fingerprintasList = consoleOutputasStr.split('=')
		fingerprint = fingerprintasList[1][:-1]

		if str(fingerprint) == SHA1ofCert:
			print "CA Certificate is Valid"
			return 1
		else:
			print "CA Certificate is Invalid. Exiting."
			return 0
	except Exception, e:
		print "Error while handling the CA certificate. Please rename CA certificate as root-ca.crt"
		print e
		return 0

# Validate sender's certificate with CA Certificate, return 1 if valid else returns 0
def validateSendersCert(cert):
	global senderName
	try:
		cmd = "openssl verify -CAfile root-ca.crt "+cert
		consoleOutput = os.popen(cmd).readlines()
		consoleOutputasStr = consoleOutput[0][:-1]

		checkString = cert+": OK"

		if (checkString == consoleOutputasStr):
			temp = consoleOutputasStr.split('.')
			senderName = temp[0]
			return 1
		else:
			return 0
	except Exception, e:
		print "Error while validating the sender's Certificate with CA Cert."
		print e
		return 0

# TODO: Used only integers, check if it should be char or int is fine as well.
# Random passphrase generator
def randomePassPhrase(myStudentId):
	random.seed(int(myStudentId))
	passphrase = str(random.randint(10000000000000000000000000000000,99999999999999999999999999999999))
	return passphrase

# TODO: Assumed that full email id is required. Not just the userID, check this before submission.
# Function used to formulate all the required values for sending message.
def sendMsg(targetEmailID):
	global sendTo
	try:
		# Validate the CA
		if validateCA() is 0:
			return 0

		temp = targetEmailID.split('@')
		senderId = temp[0]
		sendTo = senderId

		# Update the Global Certificates List
		if getCertificateListFromWebsite() == -1:
			return -1

		print "Certificate List has been updated from the website."

		# Validate Sender ID.
		sendersCertName = validateSenderId(senderId)
		if sendersCertName == -1:
			print "There is a error while sending the sending the message."
			print "SenderID is not in the CA's list."
			return -1

		# Validate Senders Certificate with CA
		if not validateSendersCert(sendersCertName):
			print "Error. Senders Certificate not validated by CA."
			return -1
		print "Target Certificate has been validated by CA."

		# Generate the session password
		sessionPwd = randomePassPhrase(myStudentId)
		passPhrase = sessionPwd	# Store this value globally.
		cmd = "echo \""+sessionPwd+"\" > key.txt"
		os.system(cmd)
		cmd = ""

		# Extract public key from sendersCertName
		cmd = "openssl x509 -pubkey -noout -in "+sendersCertName+" > "+senderId+"Public.pem"
		os.system(cmd)
		sendersPublicKey = senderId+"Public.pem"
		cmd = ""

		# Tagets public key = sendersCertName
		
		# Encrypt Session Password using target public key
		cmd = "openssl rsautl -encrypt -inkey "+sendersPublicKey+" -pubin -in "+keyFile+" -out "+encKey
		#cmd = "openssl rsautl -encrypt -inkey "+sendersPublicKey+" -pubin -in key.txt"
		#consoleOutput = os.popen(cmd).readlines()
		#print consoleOutput
		os.system(cmd)
		cmd = ""
	
		# TODO: There is some issue here when reading the encoded session key. check which is the 
		#		accurate method.
		#consoleOutput = os.popen(cmd).readlines()
		fo = open(encKey,"r+")
		encSessionPwd = fo.read()				#encSessionPwd
		fo.close()

		# Get the message and encrypt the message using AES-CBC encrypted message in base64 format
		body = raw_input("Enter the body of the message you want to send.\n")
		fo = open("body.txt","w+")
		fo.write(body+'\n')
		fo.close()

		cmd = "openssl enc -aes-256-cbc -a -salt -base64 -in body.txt -out "+encBodyFile+" -k "+sessionPwd

		os.system(cmd)		#TODO: Have to check the output of this command, what if it is not valid
		cmd = ""
		
		fo = open("encBody.txt","r+")
		encBody = fo.read()						#encBody
		fo.close()

		# Sign the session pwd encrypted under target's public key blank line & 
		# message encrypted under session pwd above

		# Get all the above to one file
		fo = open(forSignature,"w+")
		fo.write(encSessionPwd+'\n')
		fo.write("\n")							# Filename is forSignature.txt
		fo.write(encBody)			# TODO: Chek if a /n is required here or not.
		fo.close()

		# Encrypt the above file
		cmd = "openssl dgst -sha1 -sign "+privateKey+" "+forSignature+" > "+encForSignature
		os.system(cmd)
		cmd = ""
		
		fo = open(encForSignature,"r+")
		signature = fo.read()		#signature
		fo.close()

		# Form the message
		if msgMaker(encSessionPwd,encBody,signature) == -1:
			return -1

		print messageFile+" has been formed and is ready to be sent."

		return 1
	except Exception, e:
		print "Error while sending a message."
		print e
		return -1

# Function to process the received message.
def receiveMsg(incomingMsg):
	global sendTo
	try:
		# Validate the CA
		if validateCA() is 0:
			return -1

		# Update the Global Certificates List
		if getCertificateListFromWebsite() == -1:
			return -1
		print "Certificate List has been updated from the website."

		# For Header
		fo = open(incomingMsg,"r+")
		lines = fo.readlines()
		header = lines[0]
		fo.close()

		fo = open(incomingMsg,"r+")
		temp = fo.read()
		fo.close()

		temp2 = temp.split("\n\n")

		encBody = temp2[1]
		fo = open(encBodyFile,"w+")
		fo.write(encBody+'\n')
		#fo.write(encBody)
		fo.close()

		temp3 = temp2[0].split("AGE-----\n")
		encSessionPwd = temp3[1]

		fo = open(encKey,"w+")
		fo.write(encSessionPwd)
		fo.close()

		#fo = open(incomingMsg,"r+")
		temp4 = temp2[2].split("\n-----END")
		signature = temp4[0]
		
		match = re.findall(r'[\w\.-]+@[\w\.-]+', header)
		splitEmailAdd = match[0].split('@')			# Obtain the senderId.
		senderId = splitEmailAdd[0]					#TODO: Can check if the message is intended to me or not.
		sendTo = senderId

		sendersCertName = validateSenderId(senderId)	# Sender Id validity check (if a certificate exists or not)

		# Validate sender certificate with CA. (Returns 1 if valid, else returns 0)
		if not validateSendersCert(sendersCertName):
			print "Error. Senders Certificate not validated by CA."
			return -1
		
		print "Senders Certificate has been validated by CA."

		# Extract Public key of the sender from sendersCertName
		cmd = "openssl x509 -pubkey -noout -in "+sendersCertName+" > "+senderId+"Public.pem"
		os.system(cmd)
		sendersPublicKey = senderId+"Public.pem"
		cmd = ""

		# Write the signature to a meta file
		fo = open(encForSignature,"w+")
		fo.write(signature)
		fo.close()

		fo = open(forSignature,"w+")
		fo.write(encSessionPwd+"\n")
		fo.write("\n")
		fo.write(encBody+'\n')		#marker
		#fo.write(encBody)
		fo.close()

		# Verify the signature
		cmd = "openssl dgst -sha1 -verify "+sendersPublicKey+" -signature "+encForSignature+" "+forSignature
		consoleOutput = os.popen(cmd).readline()
		cmd = ""

		if consoleOutput == "Verified OK\n":
			print "The Signature on the mail has been verified."
		elif consoleOutput == "Verification Failure\n":
			print "Unable to verify the received message with the corresponding Public Key."
			print "Message discarded."
			return -1
		cmd = ""

		# Get the session key from the encrypted session key file
		cmd = "openssl rsautl -decrypt -inkey "+privateKey+" -in "+encKey+" -out "+keyFile
		os.system(cmd)
		cmd = ""

		fo = open(keyFile,"r+")
		sessionPwd = fo.read() 
		fo.close()

		# Decrypt the message
		cmd = "openssl enc -aes-256-cbc -d -base64 -in "+encBodyFile+" -out "+receivedMsgFile+" -k "+sessionPwd
		os.system(cmd)
		cmd = ""

		print "Received message has been stored in decryptedOutput.txt."

	except Exception, e:
		print "Unable to open the message."
		print e
		return -1

# Function to form a Database
def formDB():
	ctr = 0
	try:
		# Validate the CA
		validateCA()

		# Update the certificate list from the website.
		getCertificateListFromWebsite()

		totNumOfCerts = len(globalCertificatesLinks)
		certs = globalCertificatesLinks.items()

		# Get the certificates and download the PEM and validate it with the CA
		for i in xrange (0,totNumOfCerts):
			unityId = certs[i][0]
			certLink = certs[i][1][:-1]
			os.system("rm -rf "+unityId+".pem")
			urllib.urlretrieve(certLink,unityId+".pem")
			print "Certificate for "+unityId+" has been retrieved."
			
			if validateSendersCert(unityId+".pem"):
				print "Certificate for "+unityId+" has been validated by CA."
			else:
				print "Unable to Validate Certificate for "+unityId+" by the CA."
			ctr = ctr + 1

		print "\nTotal number of certificates available in the website =",totNumOfCerts
		print "Total number of certificates obtained and validated =",ctr

		print "\nCatalog of certificates is stored in "+certificatesLinksFileName+" file\n"
		return 1
	except Exception, e:
		print "Error while forming the Database of Certificates from the website."
		print "Error occured at "+unityId
		print e
		return -1

def main():
	global sendTo

	tempString1 = "\nMENU\n***********************"
	tempString2 = "****************************\n"
	tempString3 = "Enter 1: To Check the local Data Base of Ceritifcates.\n"
	tempString4 = "Enter 2: To Send a Message.\nEnter 3: To Receive a Message."
	tempString5 = "\nEnter 4: To Pull all Ceritificates from website & validate"
	tempString6 = " with the CA.\nEnter 5: To Exit.\nPlease Enter your choice here:"

	welcomeStringP1 = tempString1+tempString2+tempString3
	welcomeStringP2 = tempString4+tempString5+tempString6
	welcomeString = welcomeStringP1 + welcomeStringP2

	initialize()
	
	while True:
		case = raw_input(welcomeString)
		if case == '1':
			updateLocalDB()
			print "The local database currently contains the following."
			print localCertificates.keys()
		if case == '2':
			sendTo = raw_input("Enter the targets Email Id.\n")
			# TODO: Didn't handle the part where the domain name is not correct. Check it before submission.
			if sendMsg(sendTo) == -1:
				print "Unable to send message."
				deleteMetaFiles()
			print ""
			deleteMetaFiles()
		if case == '3':
			receivedFileName = raw_input("Enter the full name of the file received.\n")

			if receiveMsg(receivedFileName) == -1:
				print "Unable to process the received message."
				deleteMetaFiles()
			deleteMetaFiles()
		if case == '4':
			if formDB() is -1:
				print "Unable to form the Data base at this point of time."
				print "Please try again with good internet connectivity."
		if case == '5':
			break
		if case is not ('1' or '2' or '3' or '4' or '5'):
			print "\nPlease enter a valid option."

	#deleteMetaFiles()

main()
