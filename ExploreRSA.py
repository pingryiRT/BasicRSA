# https://www.dlitz.net/software/pycrypto/api/current/Crypto.PublicKey.RSA-module.html#generate
import Crypto 
import json
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

#-----------------------------------------------------------------------------------------------------------------#
					#-----Basic Encryption w/ Public Decryption w/ Private-----#
bobKey = RSA.generate(2048)

#Keys in string form (NOTE: HAD TO SWITCH FROM BINARY ENCODING BECAUSE THAT WAS NOT SUPPORTED BY TXT FILE
pub = bobKey.publickey().exportKey('PEM') # https://www.dlitz.net/software/pycrypto/api/2.5/Crypto.PublicKey.RSA._RSAobj-class.html
pri = bobKey.exportKey('PEM') # this exportKey method serializes the key object

# TESTING WHETHER OR NOT KEYS CAN BE EXPORTED TO FILE AND LATER REUSED IN A DIFFERENT FILE
f = open("bobPubKey.txt", "w")
d = open("bobPriKey.txt", "w")

#keyObjects = [pub, pri]
#stringKeys = json.dumps(keyObjects)
#json.dump(stringKeys, f)

f.write(pub)
d.write(pri) 
f.close()
d.close()

aliceKey = RSA.generate(1024)

pubAlice = aliceKey.publickey().exportKey('PEM')
priAlice = aliceKey.exportKey('PEM') #string form

#Import the keys
bobPublicKey = RSA.importKey(pub)
bobPrivateKey = RSA.importKey(pri) #takes in string, returns RSA object


alicePublicKey = RSA.importKey(pubAlice)
alicePrivateKey = RSA.importKey(priAlice)

message = "iRT Distributed Computing"
print("Original Message: {}".format(message)) 

#Returns a tuple - first element is the encrypted text. The second parameter is just a plaintext that is ignored
encryptedMessage = bobPublicKey.encrypt(message, 'x')[0]  #https://www.dlitz.net/software/pycrypto/api/current/Crypto.PublicKey.RSA._RSAobj-class.html#encrypt

#print("Encrypted Message: {}".format(encryptedMessage))

#Decrypt using private key 
decryptedMessage = bobPrivateKey.decrypt(encryptedMessage)

print("Decrypted Message Using Private Key: {}".format(decryptedMessage))
print


#-----------------------------------------------------------------------------------------------------------------#
					#-----Basic Signing of a Message and Verifying-----#
text = "Hello"

sha256Hash = SHA256.new(text).digest() #create the hash

#print("The hash: {}".format(sha256Hash))

signature = bobKey.sign(sha256Hash, '') #Bob signed it 

#Alice receives the signature and the hash in order to verify
print("When Alice tries to verify that Bob sent her the message, she finds that it is: {}".format(bobPublicKey.verify(sha256Hash, signature))) #given signature - returns true if signature is found to verify the hash
print

#-----------------------------------------------------------------------------------------------------------------#
					#-----Combine Verification and Encryption-----#

secretCode = "Peer to peer networks"
print("Original Message: {}".format(secretCode))

# Step 1: Encrypt with Alice's public key
encryptedSecretCode = alicePublicKey.encrypt(secretCode, 'x')[0]

# Step 2: Bob will sign with his RSA object to prove that he sent the message
hash = SHA256.new(encryptedSecretCode).digest()
bobSignature = bobKey.sign(hash, '')

# Step 3: Alice should be able to verify that Bob sent the message and decrypt it with her private key
if bobPublicKey.verify(hash, bobSignature): #if the signature that was sent is valid, then Alice knows the code is from Bob
	code = alicePrivateKey.decrypt(encryptedSecretCode)

print("Result: {}".format(code))

#-----------------------------------------------------------------------------------------------------------------#
