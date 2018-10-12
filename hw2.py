import math
import sys
import binascii
import hw1
import time
import random
import os

if not os.path.exists('Alice'):
	os.makedirs('Alice')
if not os.path.exists('Bob'):
	os.makedirs('Bob')
	
random.seed()
alice = open('Alice/Alice.txt', "w")
bob = open('Bob/Bob.txt', "w")



print "Welcome to the Needham-Schroeder Protocol Simulator."
print "In this instance, Alice.txt will attempt to set up a secure session key with Bob.txt"
print "Press enter to advance the simulation"

raw_input()
#generate keys using Diffie-Hellman keyshare simulation

#public data
prime = 1021
p_root = 260

#server
Svalue = random.randint(0, 1021)
SNewvalue = pow(p_root, Svalue, prime)

#alice
alice.write("Initialized at time " + str(time.time()) + "\n")
Avalue = random.randint(0, 1021)
alice.write("Used DH value " + str(Avalue))
ANewvalue = pow(p_root, Avalue, prime)
alice.write(" and got : " + str(ANewvalue) + '\n')

#bob
bob.write("Initialized at time " + str(time.time()) + "\n")
Bvalue = random.randint(0, 1021)
bob.write("Used DH value " + str(Bvalue))
BNewvalue = pow(p_root, Bvalue, prime)
bob.write(" and got : " + str(BNewvalue) + '\n')

#SNewvalue, BNewvalue, and ANewvalue are all made public
#server
Akey = pow(ANewvalue, Svalue, prime)
Bkey = pow(BNewvalue, Svalue, prime)
#alice
Alicekey = pow(SNewvalue, Avalue, prime)
Alicekey = "{0:b}".format(Alicekey).zfill(10)
alice.write("My key: " + Alicekey + "\n")
alice.close()

#bob
Bobkey = pow(SNewvalue, Bvalue, prime)
Bobkey = "{0:b}".format(Bobkey).zfill(10)
bob.write("My key: " + Bobkey + "\n")
bob.close()



Ka = ""
Ka = "{0:b}".format(Akey).zfill(10)
print "Alice has been given the key: " + Ka

Kb = ""
Kb = "{0:b}".format(Bkey).zfill(10)
print "Bob has been given the key: " + Kb

#randomly generate a 10 bit session key
Ks = ""
for i in range(0, 10):
	Ks += str(random.randint(0, 1))
print "The session key that will be distributed is: " + Ks






raw_input()
print "Encrypting data and sending to Alice"

IDA = "Alice"
IDB = "Bob"
Nonce1 = "Request Granted"

encryptB = open('encryptWithKB.txt', "w")
encryptB.write(str(Ks) + '\n' + IDA + '\n' + str(time.time()))
encryptB.close()
hw1.enc('encrypt', 'encryptWithKB.txt', 'encryptWithKA.txt', Kb)

encryptA = open('encryptWithKA.txt', "a")
encryptA.write('\n' + str(Ks) + '\n' + IDB + '\n' + str(time.time()))
encryptA.close()
hw1.enc('encrypt', 'encryptWithKA.txt', 'Alice/decryptWithKA.txt', Ka)
alice = open('Alice/Alice.txt', "a")
alice.write(str(time.time()) + ': recieved data from server\n')
alice.close()







raw_input()
print "Decrypting Alice's data, sending data to Bob"

#As alice, alice has access to key Alicekey
hw1.enc('decrypt', 'Alice/decryptWithKA.txt', 'Alice/decrypted.txt', Alicekey)
decrypted = open('Alice/decrypted.txt', "r")

#first line is to be sent to Bob
first_line = decrypted.readline()
decryptB = open('Bob/decryptWithKB.txt', "w")
decryptB.write(first_line[:-1])
decryptB.close()

aliceKs = decrypted.readline()[:-1]
print "Alice retrieved Ks: " + aliceKs
print "Alice retrieved IDB: " + decrypted.readline()[:-1]
timestamp = decrypted.readline()
timediff = abs(float(timestamp) - time.time())
if timediff > 10:
	print "Alice should reject data, more than 10 second time difference with encryption time"
else:
	print "Alice should accept data, only %.2g second time difference with encryption time" % (timediff,)
decrypted.close()

bob = open('Bob/Bob.txt', "a")
bob.write(str(time.time()) + ': recieved data from server\n')
bob.close()






raw_input()
print "Decrypting Bob's data"


#As Bob, Bob has access to key Bobkey
hw1.enc('decrypt', 'Bob/decryptWithKB.txt',  'Bob/decrypted.txt', Bobkey)

decrypted = open('Bob/decrypted.txt', "r")
bobKs = decrypted.readline()[:-1]
print "Bob retrieved Ks: " + bobKs
print "Bob retrieved IDA: " + decrypted.readline()[:-1]
timestamp = decrypted.readline()
timediff = abs(float(timestamp) - time.time())
if timediff > 10:
	print "Bob should reject data, more than 10 second time difference with encryption time"
else:
	print "Bob should accept data, only %.2g second time difference with encryption time" % (timediff,)
decrypted.close()
print





raw_input()
print "Testing the connection:"
print
print "Bob encrypting a message with his Ks"
message = open('Bob/message.txt', "w")
message.write('Howdy')
message.close()
hw1.enc('encrypt', 'Bob/message.txt', 'Alice/decryptWithKS.txt', bobKs)

print "Alice decrypting that message"

hw1.enc('decrypt', 'Alice/decryptWithKS.txt', 'Alice/message.txt', aliceKs)
message = open('Alice/message.txt', "r")
print "Alice recieved: " + message.readline()
message.close()





raw_input()
print "Alice encrypting a message with her Ks"
message = open('Alice/message.txt', "w")
message.write('Rowdy')
message.close()
hw1.enc('encrypt', 'Alice/message.txt', 'Bob/decryptWithKS.txt', bobKs)

print "Bob decrypting that message"

hw1.enc('decrypt', 'Bob/decryptWithKS.txt', 'Bob/message.txt', aliceKs)
message = open('Bob/message.txt', "r")
print "Bob recieved: " + message.readline()
message.close()











