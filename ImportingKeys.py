import Crypto 
import json
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256


f = open("bobPubKey.txt", "r")
d = open("bobPriKey.txt", "r")

stringPublic = f.read()
stringPrivate = d.read()

bobPublicKey = RSA.importKey(stringPublic) #serialize into RSA objects
bobPrivateKey = RSA.importKey(stringPrivate)
 
string = "Testing the imported keys"
print("Original Message: {}".format(string)) 

encryptedString = bobPublicKey.encrypt(string, 'x')[0] 
decryptedString = bobPrivateKey.decrypt(encryptedString) 

print("Decyrpted Message: {}".format(decryptedString))



#stringKeys = json.load(f) #use JSON to take in and deserialize the "string list" 

#listKeys = [str(i) for i in stringKeys.strip("[\"-----BEGIN PUBLIC KEY-----\"").split(',')]

#print(listKeys)

# stringPublic = listKeys[0]
# stringPrivate = listKeys[1]
# 
# bobPublicKey = RSA.importKey(stringPublic) #serialize into RSA objects
# bobPrivateKey = RSA.importKey(stringPrivate)
# 
# string = "Testing the imported keys"
# print("Original Message: {}".format(string))
# 
# encryptedString = bobPublicKey.encrypt(string)
# decryptedString = bobPrivateKey.decrypt(encryptedString) 
# 
# print("Decyrpted Message: {}".format(decryptedString))

