from binascii import hexlify, unhexlify
import hmac, random, sys
from hashlib import md5
import numpy as np

def ReverseCipher(plaintext):
	ciphertext = ''
	i = len(plaintext)-1
	while i>=0:
		ciphertext = ciphertext+plaintext[i]
		i -=1
	return ciphertext

class OTP:
	def OTPSuperMsg(msg1, msg2):
		hex1, hex2 = hexlify(msg1), hexlify(msg2)
		cipher1, cipher2 = int(hex1, 16), int(hex2, 16)
		msg = cipher1*cipher2
		return msg

	def EncryptOTP(msg, key):
		Skey = int(msg, 16)^key
		return Skey

	def DecryptOTP(msg, key):
		xor = msg^key
		tohex = format(xor, 'x')
		evenpad = ('0'*(len(tohex)%2))+tohex
		plaintext = unhexlify(evenpad)
		return plaintext

def md5_(key, msg):
	key = b'{}'.format(key)
	H = hmac.new(key, b'', md5)
	H.update(msg)
	return H.digest()

class SubsCipher:
	def EncryptSub(n, plaintext):
		key = 'abcdefghijklmnopqrstuvwxyz'
		result = ''
		for i in plaintext.lower():
			try:
				j = (key.index(i)+n)%26
				result+=key[j]
			except ValueError:
				result+=i
		return result.lower()

	def DecryptSub(n, ciphertext):
		key = 'abcdefghijklmnopqrstuvwxyz'
		result = ''
		for i in ciphertext:
			try:
				j = (key.index(i)-n)%26
				result+=key[j]
			except ValueError:
				result+=i
		return result

class Caesar:
	def EncryptCaesar(n, plaintext):
		key = 'abcdefghijklmnopqrstuvwxyz'
		result = ''
		for i in plaintext.lower():
			try:
				j = (key.index(i)+n)%26
				result += key[j]
			except ValueError:
				result += i
		return result.lower()

	def DecryptCaesar(n, ciphertext):
		key = 'abcdefghijklmnopqrstuvwxyz'
		result = ''
		for i in ciphertext:
			try:
				j = (key.index[i]-n)%26
				result += key[j]
			except ValueError:
				result += 1
		return result

def ROT13(n, plaintext):
	key = 'abcdefghijklmnopqrstuvwxyz'
	result = ''
	for i in plaintext.lower():
		try:
			j = (key.index[i]-n)%26
			result+=key[j]
		except ValueError:
			result += i
	return result.lower()

def AtBash(text):
	alphabets = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
	reverse = list(reversed(alphabets))
	code_dict = dict(zip(alphabets, reverse))
	chars = list(text.upper())
	result = ""
	for c in chars:
		if c in code_dict:
			result += code_dict.get(c)
		else:
			result+=c
	return result


class Vigenere:
	def key_vigenere(key):
		KeyArray = []
		for i in range(0, len(key)):
			elem = ord(key[i])-65
			KeyArray.append(elem)
		return KeyArray

	def EncryptVig(key, plaintext):
		secret = "".join([chr((ord(plaintext[i])-ord('A')+key[i%len(key)])for i in range(len(plaintext)))])
		return secret

	def DecryptVig(key, ciphertext):
		text = "".join([chr((ord(ciphertext)-ord('A')-key[i%len(key)])for i in range(len(ciphertext)))])
		return text

def Playfair_box_shift(i1, i2):
	r1 = i1/5
	r2 = i2/5
	c1 = i1 % 5
	c2 = i2 % 5
	out_r1 = r1
	out_c1 = c2
	out_r2 = r2
	out_c2 = c1
	if r1 == r2:
		out_c1 = (c1 + 1) % 5
		out_c2 = (c2 + 1) % 5
	elif c1 == c2:
		out_r1 = (r1 + 1) % 5
		out_r2 = (r2 + 1) % 5
	return out_r1*5 + out_c1, out_r2*5 + out_c2
	
def EncryptPlayFair(plaintext):
	random.shuffle(words)
	seed = "".join(words[:10]).replace('j','i')
	alpha = 'abcdefghiklmnopqrstuvwxyz'
	suffix = "".join(sorted(list(set(alpha) - set(seed))))
	seed_set = set()
	prefix = ""
	for letter in seed:
		if not letter in seed_set:
			seed_set.add(letter)
			prefix += letter
	key = prefix + suffix
	secret = ""
	for i in range(0,len(plain),2):
		chr1 = plain[i]
		chr2 = plain[i+1]
		if chr1 == chr2:
			chr2 = 'X'
		i1 = key.find(chr1.lower())
		i2 = key.find(chr2.lower())
		ci1, ci2 = Playfair_box_shift(i1, i2)
		secret += key[ci1] + key[ci2]
	return secret, key

def Playfair_box_shift_dec(i1, i2):
	r1 = i1/5
	r2 = i2/5
	c1 = i1 % 5
	c2 = i2 % 5
	out_r1 = r1
	out_c1 = c2
	out_r2 = r2
	out_c2 = c1
	if r1 == r2:
		out_c1 = (c1 - 1) % 5
		out_c2 = (c2 - 1) % 5
	elif c1 == c2:
		out_r1 = (r1 - 1) % 5
		out_r2 = (r2 - 1) % 5
	return out_r1*5 + out_c1, out_r2*5 + out_c2

def Playfair_dec(ciphertext, sharedkey):
	seed = "".join(sharedkey).replace('j','i')
	alpha = 'abcdefghiklmnopqrstuvwxyz'
	suffix = "".join(sorted(list(set(alpha) - set(seed))))
	seed_set = set()
	prefix = ""
	for letter in seed:
		if not letter in seed_set:
			seed_set.add(letter)
			prefix += letter
	key = prefix + suffix
	plaintext = ""
	for i in range(0,len(ciphertext),2):
		chr1 = ciphertext[i]
		chr2 = ciphertext[i+1]
		print(chr1, chr2)
		if chr1 == chr2:
			chr2 = 'X'
		i1 = key.find(chr1.lower())
		i2 = key.find(chr2.lower())
		ci1, ci2 = Playfair_box_shift_dec(i1, i2)
		plaintext += key[ci1] + key[ci2]
	return plaintext


def Enc_Hill2X2(key, plaintext):
	check_length = 0
	if len(plain)%2 != 0:
		plain+="0"
		check_length = 1
	row = 2
	col = int(len(plain)/2)
	msg2d = np.zeros((row, col), dtype = int)

	itr1 = 0
	itr2 = 0
	for i in range(len(plain)):
		if i%2 == 0:
			msg2d[0][itr1] = int(ord(plaintext[i])-65)
			itr+=1
		else:
			msg2d[1][itr2] = int(ord(plain[i]) - 65)
			itr2 += 1
	key2d = np.zeros((2,2), dtype=int)
	itr3 = 0
	for i in range(2):
		for j in range(2):
			key2d[i][j] = ord(key[itr3]) - 65
			itr3 += 1
	print (key2d)
	deter = key2d[0][0] * key2d[1][1] - key2d[0][1] * key2d[1][0]
	deter = deter % 26
	for i in range(26):
		temp_inv = deter * i
		if temp_inv % 26 == 1:
			mul_inv = i
			break
		else:
			continue
	if mul_inv == -1:
		print("Invalid key")
		sys.exit()
		encryp_text = ""
		itr_count = int(len(plain)/2)
		if check_length == 0:
			for i in range(itr_count):
				temp1 = msg2d[0][i] * key2d[0][0] + msg2d[1][i] * key2d[0][1]
				encryp_text += chr((temp1 % 26) + 65)
				temp2 = msg2d[0][i] * key2d[1][0] + msg2d[1][i] * key2d[1][1]
				encryp_text += chr((temp2 % 26) + 65)
	else:
		for i in range(itr_count-1):
			temp1 = msg2d[0][i] * key2d[0][0] + msg2d[1][i] * key2d[0][1]
			encryp_text += chr((temp1 % 26) + 65)
			temp2 = msg2d[0][i] * key2d[1][0] + msg2d[1][i] * key2d[1][1]
			encryp_text += chr((temp2 % 26) + 65)
			print("Encrypted text: {}".format(encryp_text))
	return encryp_text

def Decr_Hill2X2(key, ciphertext):
	check_length = 0
	if len(cipher) % 2 != 0:
		cipher += "0"
		check_length = 1

	row = 2	
	col = int(len(cipher)/2)
	msg2d = np.zeros((row, col), dtype=int)
	itr1 = 0
	itr2 = 0
	for i in range(len(cipher)):
		if i%2 == 0:
			msg2d[0][itr1]= int(ord(cipher[i]) - 65)
			itr1 += 1
		else:
			msg2d[1][itr2] = int(ord(cipher[i]) - 65)
			itr2 += 1

	key2d = np.zeros((2,2), dtype=int)
	itr3 = 0
	for i in range(2):
		for j in range(2):
			key2d[i][j] = ord(key[itr3]) - 65
			itr3 += 1

	deter = key2d[0][0] * key2d[1][1] - key2d[0][1] * key2d[1][0]
	deter = deter % 26
	for i in range(26):
		temp_inv = deter * i
		if temp_inv % 26 == 1:
			mul_inv = i
			break
		else:
			continue

	key2d[0][0], key2d[1][1] = key2d[1][1], key2d[0][0]
	key2d[0][1] *= -1
	key2d[1][0] *= -1
	key2d[0][1] = key2d[0][1] % 26
	key2d[1][0] = key2d[1][0] % 26

	for i in range(2):
		for j in range(2):
			key2d[i][j] *= mul_inv

	for i in range(2):
		for j in range(2):
			key2d[i][j] = key2d[i][j] % 26
	decryp_text = ""
	itr_count = int(len(cipher)/2)
	if check_length == 0:
		for i in range(itr_count):
			temp1 = msg2d[0][i] * key2d[0][0] + msg2d[1][i] * key2d[0][1]
			decryp_text += chr((temp1 % 26) + 65)
			temp2 = msg2d[0][i] * key2d[1][0] + msg2d[1][i] * key2d[1][1]
			decryp_text += chr((temp2 % 26) + 65)

	else:
		for i in range(itr_count-1):
			temp1 = msg2d[0][i] * key2d[0][0] + msg2d[1][i] * key2d[0][1]
			decryp_text += chr((temp1 % 26) + 65)
			temp2 = msg2d[0][i] * key2d[1][0] + msg2d[1][i] * key2d[1][1]
			decryp_text += chr((temp2 % 26) + 65)

	print("Decrypted text: {}".format(decryp_text))

def get_number_location(key, keyword_num_list):
	num_loc = ""
	for i in range(len(key) + 1):
		for j in range(len(key)):
			if keyword_num_list[j] == i:
				num_loc += str(j)
	return num_loc

def keyword_num_assign(key):
	alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	keyword_num_list = list(range(len(key)))
	init = 0
	for i in range(len(alpha)):
		for j in range(len(key)):
			if alpha[i] == key[j]:
				init += 1
			keyword_num_list[j] = init
	return keyword_num_list

def print_grid(plain_text, key):
	keyword_num_list = keyword_num_assign(key)
	for i in range(len(key)):
		print(key[i], end = " ", flush=True)
	print()
	for i in range(len(key)):
		print(str(keyword_num_list[i]), end=" ", flush=True)
	print()

	print("-------------------------")
	# in case characters don't fit the entire grid perfectly.
	extra_letters = len(plain_text) % len(key)
	dummy_characters = len(key) - extra_letters
	if extra_letters != 0:
		for i in range(dummy_characters):
			plain_text += "."
	num_of_rows = int(len(plain_text) / len(key))
	# Converting message into a grid
	arr = [[0] * len(key) for i in range(num_of_rows)]
	z = 0
	for i in range(num_of_rows):
		for j in range(len(key)):
			arr[i][j] = plain_text[z]
			z += 1
	for i in range(num_of_rows):
		for j in range(len(key)):
			print(arr[i][j], end=" ", flush=True)
		print()

def ColumnTranscriptionEncrypt(key, plaintext):
	keyword_num_list = keyword_num_assign(key)
	num_of_rows = int(len(plain_text) / len(key))

	arr = [[0] * len(key) for i in range(num_of_rows)]
	z = 0

	for i in range(num_of_rows):
		for j in range(len(key)):
			arr[i][j] = plain_text[z]
			z += 1
	num_loc = get_number_location(key, keyword_num_list)
	cipher_text = ""
	k = 0
	for i in range(num_of_rows):
		if k == len(key):
			break
		else:
			d = int(num_loc[k])
		for j in range(num_of_rows):
			cipher_text += arr[j][d]
			k += 1
	return cipher_text

def cipher_decryption(encrypted, key):
	keyword_num_list = keyword_num_assign(key)
	num_of_rows = int(len(encrypted) / len(key))
	num_loc = get_number_location(key, keyword_num_list)
	# Converting message into a grid
	arr = [[0] * len(key) for i in range(num_of_rows)]
	# decipher
	plain_text = ""
	k = 0
	itr = 0
	for i in range(len(encrypted)):
		d = 0
		if k == len(key):
			k = 0
		else:
			d: int = int(num_loc[k])
		for j in range(num_of_rows):
			arr[j][d] = encrypted[itr]
			itr += 1
		if itr == len(encrypted):
			break
		k += 1
	print()
	for i in range(num_of_rows):
		for j in range(len(key)):
			plain_text += str(arr[i][j])
	return plain_text

def AffineEncrypt(plaintext, key):
	'''
	Encryption = (a*x+b)%26
	'''
	return ''.join([chr(((key[0]*(ord(t)-ord('A')) +key[1])%26)+ord('A'))
		for t in plaintext.upper().replace(' ','')])

def AffineDecrypt(ciphertext, key):
	'''
	Decryption = (a^-1 * (x - b)) % 26
	'''
	return ''.join([chr(((modinv(key[0], 26)*(ord(c) - ord('A') - key[1]))
		% 26) + ord('A')) for c in ciphertext])

