import math
import sys
import binascii


def enc(operation, input, output, key):

	#get keys
	lkey = key[2] + key[4] + key[1] + key[6] + key[3]
	rkey = key[9] + key[0] + key[8] + key[7] + key[5]
	#left shift
	lkey2 = lkey[1] + lkey[2] + lkey[3] + lkey[4] + lkey[0]
	rkey2 = rkey[1] + rkey[2] + rkey[3] + rkey[4] + rkey[0]
	#p8
	key1 = rkey2[0] + lkey2[2] + rkey2[1] + lkey2[3] + rkey2[2] + lkey2[4] + rkey2[4] + rkey2[3]
	#left shift
	lkey3 = lkey2[1] + lkey2[2] + lkey2[3] + lkey2[4] + lkey2[0]
	rkey3 = rkey2[1] + rkey2[2] + rkey2[3] + rkey2[4] + rkey2[0]
	#p8
	key2 = rkey3[0] + lkey3[2] + rkey3[1] + lkey3[3] + rkey3[2] + lkey3[4] + rkey3[4] + rkey3[3]

	#swap the keys if decrypting
	if operation == 'decrypt':
		tmp = key1
		key1 = key2
		key2 = tmp
		print "decrypting"
	else:
		print "encrypting"

	#set up s-boxes
	s0 = [
		['01', '00', '11', '10'],
		['11', '10', '01', '00'],
		['00', '10', '01', '11'],
		['11', '01', '11', '10']
	]

	s1 = [
		['00', '01', '10', '11'],
		['10', '00', '01', '11'],
		['11', '00', '01', '00'],
		['10', '01', '00', '11']
	]

	#read data byte by byte
	with open(input, "rb") as in_file, open(output, "wb") as out_file:
		while True:
			piece = in_file.read(1)
			if(piece == ""):
				break
			
			#convert byte to bits
			bits = bin(ord(piece))[2:]
			bits = '00000000'[len(bits):] + bits
			#initial permutation
			bits2 = bits[1] + bits[5] + bits[2] + bits[0] + bits[3] + bits[7] + bits[4] + bits[6]
			iterations = 0
			#split into two halves
			lbits = bits2[:4]
			rbits = bits2[4:]
			#run this loop twice
			while True:
				#F
				#expansion permutation
				rbits2 = rbits[3] + rbits[0] + rbits[1] + rbits[2] + rbits[1] + rbits[2] + rbits[3] + rbits[0]
				
				#perform 8bit xor: rbits2 with key, keeping in mind which key to use
				xor = "";
				for i in range(0, 8):
					if(rbits2[i] == '1'):
						if(iterations == 0 and key1[i] == '1'):
							xor += '0';
						elif(iterations == 1 and key2[i] == '1'):
							xor += '0';
						else:
							xor += '1';
					elif iterations == 0 and key1[i] == '1':
						xor += '1';
					elif iterations == 1 and key2[i] == '1':
						xor += '1';
					else:
						xor += '0';
				#get s-box indeces
				lrow = int(xor[1:3], 2)
				lcol = int(xor[0] + xor[3], 2)
				rrow = int(xor[5:7], 2)
				rcol = int(xor[4] + xor[7], 2)
				
				#get result from s-boxes
				Sres = s0[lrow][lcol] + s1[rrow][rcol]
				
				#4bit permutation
				rbits2 = Sres[1] + Sres[3] + Sres[2] + Sres[0]
				#4bit xor: rbits2 with lbits
				xor = ""
				for i in range(0, 4):
					if(rbits2[i] == '1'):
						if(lbits[i] == '1'):
							xor += '0';
						else:
							xor += '1';
					elif lbits[i] == '1':
						xor += '1';
					else:
						xor += '0';
				
				if iterations == 1:
					#stop when two rounds have been completed
					lbits = xor
					break
				#if continuing, swap rbits and lbits for next iterations
				iterations += 1
				lbits = rbits
				rbits = xor
				
			#construct ciphertext
			ciphertext = lbits + rbits
			#perform reverse permutation
			ciphertext2 = ciphertext[3] + ciphertext[0] + ciphertext[2] + ciphertext[4] + ciphertext[6] + ciphertext[1] + ciphertext[7] + ciphertext[5]
			#convert to ascii and write to file
			ciphertext2 = int(ciphertext2, 2)
			out_file.write(chr(ciphertext2))
	in_file.close()
	out_file.close()
	print "finished"



