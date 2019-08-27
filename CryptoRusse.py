# coding: utf-8
import random, string, base64, binascii, codecs, time, sys, os, hashlib
from base64 import b64encode, b64decode, b32encode, b32decode, b16encode, b16decode
from Crypto.Cipher import AES
from termcolor import colored
def stop():
	print(colored('[!] Stopping CryptoRusse...', 'red'))
	time.sleep(0.5)
	print('[!] Good bye !')
	sys.exit()

def stop2():
	print(colored('\n[!] Stopping CryptoRusse...', 'red'))
	time.sleep(0.5)
	print('[!] Good bye !')
	sys.exit()

def hashes():
		print('[1] MD5 Encrypt text')
		print('[2] SHA-1 Encrypt text')
		print('[3] SHA-224 Encrypt text')
		print('[4] SHA-256 Encrypt text')
		print('[5] SHA-384 Encrypt text')
		print('[6] SHA-512 Encrypt text')
		print('[7] SHA3-224 Encrypt text')
		print('[8] SHA3-256 Encrypt text')
		print('[9] SHA3-384 Encrypt text')
		print('[10] SHA3-512 Encrypt text')
		print('[11] SHAKE-128 Encrypt text')
		print('[12] SHAKE-256 Encrypt text')
		print('[13] BLAKE2b Encrypt text')
		print('[14] BLAKE2s Encrypt text')
		print('[15] Go to main menu')
		while 1:
			x = input('[*]>>')
			if x == '1':
				print('[?] Type the text you want to encrypt into MD5')
				a = input('[*]>>')
				print('[!] This is the encrypted text into MD5 :', hashlib.md5(a.encode('utf-8')).hexdigest())
				print('[1] Go to the main menu')
				print('[2] Quit CryptoRusse')
				while 1:
					finalchoice = input('[*]>>')
					if finalchoice == '1':
						mainmenu()
					elif finalchoice == '2':
						stop()
					else:
						print(colored('[!] You need to choose a number (1 or 2)', 'red'))
			elif x == '2':
				print('[?] Type the text you want to encrypt into SHA-1')
				a = input('[*]>>')
				print('[!] This is the encrypted text into SHA-1 :', hashlib.sha1(a.encode('utf-8')).hexdigest())
				print('[1] Go to the main menu')
				print('[2] Quit CryptoRusse')
				while 1:
					finalchoice = input('[*]>>')
					if finalchoice == '1':
						mainmenu()
					elif finalchoice == '2':
						stop()
					else:
						print(colored('[!] You need to choose a number (1 or 2)', 'red'))
			elif x == '3':
				print('[?] Type the text you want to encrypt in SHA-224')
				a = input('[*]>>')
				print('[!] This is the encrypted text into SHA-224 :', hashlib.sha224(a.encode('utf-8')).hexdigest())
				print('[1] Go to the main menu')
				print('[2] Quit CryptoRusse')
				while 1:
					finalchoice = input('[*]>>')
					if finalchoice == '1':
						mainmenu()
					elif finalchoice == '2':
						stop()
					else:
						print(colored('[!] You need to choose a number (1 or 2)', 'red'))
			elif x == '4':
				print('[?] Type the text you want to encrypt in SHA-256')
				a = input('[*]>>')
				print('[!] This is the encrypted text into SHA-256 :', hashlib.sha256(a.encode('utf-8')).hexdigest())
				print('[1] Go to the main menu')
				print('[2] Quit CryptoRusse')
				while 1:
					finalchoice = input('[*]>>')
					if finalchoice == '1':
						mainmenu()
					elif finalchoice == '2':
						stop()
					else:
						print(colored('[!] You need to choose a number (1 or 2)', 'red'))
			elif x == '5':
				print('[?] Type the text you want to encrypt into SHA-384')
				a = input('[*]>>')
				print('[!] This is the encrypted text into SHA-384 :', hashlib.sha384(a.encode('utf-8')).hexdigest())
				print('[1] Go to the main menu')
				print('[2] Quit CryptoRusse')
				while 1:
					finalchoice = input('[*]>>')
					if finalchoice == '1':
						mainmenu()
					elif finalchoice == '2':
						stop()
					else:
						print(colored('[!] You need to choose a number (1 or 2)', 'red'))
			elif x == '6':
				print('[?] Type the text you want to encrypt into SHA-512')
				a = input('[*]>>')
				print('[!] This is the encrypted text into SHA-512 :', hashlib.sha512(a.encode('utf-8')).hexdigest())
				print('[1] Go to the main menu')
				print('[2] Quit CryptoRusse')
				while 1:
					finalchoice = input('[*]>>')
					if finalchoice == '1':
						mainmenu()
					elif finalchoice == '2':
						stop()
					else:
						print(colored('[!] You need to choose a number (1 or 2)', 'red'))
			elif x == '7':
				print('[?] Type the text you want to encrypt into SHA3-224')
				a = input('[*]>>')
				print('[!] This is the encrypted text into SHA3-224 :', hashlib.sha3_224(a.encode('utf-8')).hexdigest())
				print('[1] Go to the main menu')
				print('[2] Quit CryptoRusse')
				while 1:
					finalchoice = input('[*]>>')
					if finalchoice == '1':
						mainmenu()
					elif finalchoice == '2':
						stop()
					else:
						print(colored('[!] You need to choose a number (1 or 2)', 'red'))
			elif x == '8':
				print('[?] Type the text you want to encrypt into SHA3-256')
				a = input('[*]>>')
				print('[!] This is the encrypted text into SHA3-256 :', hashlib.sha3_256(a.encode('utf-8')).hexdigest())
				print('[1] Go to the main menu')
				print('[2] Quit CryptoRusse')
				while 1:
					finalchoice = input('[*]>>')
					if finalchoice == '1':
						mainmenu()
					elif finalchoice == '2':
						stop()
					else:
						print(colored('[!] You need to choose a number (1 or 2)', 'red'))
			elif x == '9':
				print('[?] Type the text you want to encrypt into SHA3-384')
				a = input('[*]>>')
				print('[!] This is the encrypted text into SHA3-384 :', hashlib.sha3_384(a.encode('utf-8')).hexdigest())
				print('[1] Go to the main menu')
				print('[2] Quit CryptoRusse')
				while 1:
					finalchoice = input('[*]>>')
					if finalchoice == '1':
						mainmenu()
					elif finalchoice == '2':
						stop()
					else:
						print(colored('[!] You need to choose a number (1 or 2)', 'red'))
			elif x == '10':
				print('[?] Type the text you want to encrypt into SHA3-512')
				a = input('[*]>>')
				print('[!] This is the encrypted text into SHA3-512 :', hashlib.sha3_512(a.encode('utf-8')).hexdigest())
				print('[1] Go to the main menu')
				print('[2] Quit CryptoRusse')
				while 1:
					finalchoice = input('[*]>>')
					if finalchoice == '1':
						mainmenu()
					elif finalchoice == '2':
						stop()
					else:
						print(colored('[!] You need to choose a number (1 or 2)', 'red'))
			elif x == '11':
				print('[?] Type the text you want to encrypt into SHAKE-128 (256 lenght)')
				a = input('[*]>>')
				print('[?] Output bits (512 bits = 128 letters and numbers, 1024 bits = 256 letters and numbers, bits ÷ 4 = numbers and letters)')
				n = input('[*]>>')
				print('[!] This is the encrypted text into SHAKE-128 :', hashlib.shake_128(a.encode('utf-8')).hexdigest(int(int(n)/4/2)))
				print('[1] Go to the main menu')
				print('[2] Quit CryptoRusse')
				while 1:
					finalchoice = input('[*]>>')
					if finalchoice == '1':
						mainmenu()
					elif finalchoice == '2':
						stop()
					else:
						print(colored('[!] You need to choose a number (1 or 2)', 'red'))
			elif x == '12':
				print('[?] Type the text you want to encrypt into SHAKE-256')
				a = input('[*]>>')
				print('[?] Output bits (512 bits = 128 letters and numbers, 1024 bits = 256 letters and numbers, bits ÷ 4 = numbers and letters)')
				n = input('[*]>>')
				print('[!] This is the encrypted text into SHAKE-256 :', hashlib.shake_256(a.encode('utf-8')).hexdigest(int(int(n)/4/2)))
				print('[1] Go to the main menu')
				print('[2] Quit CryptoRusse')
				while 1:
					finalchoice = input('[*]>>')
					if finalchoice == '1':
						mainmenu()
					elif finalchoice == '2':
						stop()
					else:
						print(colored('[!] You need to choose a number (1 or 2)', 'red'))
			elif x == '13':
				print('[?] Type the text you want to encrypt into BALKE2b (256 lenght)')
				a = input('[*]>>')
				print('[!] This is the encrypted text into BLAKE2b :', hashlib.blake2b(a.encode('utf-8')).hexdigest())
				print('[1] Go to the main menu')
				print('[2] Quit CryptoRusse')
				while 1:
					finalchoice = input('[*]>>')
					if finalchoice == '1':
						mainmenu()
					elif finalchoice == '2':
						stop()
					else:
						print(colored('[!] You need to choose a number (1 or 2)', 'red'))
			elif x == '14':
				print('[?] Type the text you want to encrypt into BALKE2s (256 lenght)')
				a = input('[*]>>')
				print('[!] This is the encrypted text into BLAKE2s :', hashlib.blake2s(a.encode('utf-8')).hexdigest())
				print('[1] Go to the main menu')
				print('[2] Quit CryptoRusse')
				while 1:
					finalchoice = input('[*]>>')
					if finalchoice == '1':
						mainmenu()
					elif finalchoice == '2':
						stop()
					else:
						print(colored('[!] You need to choose a number (1 or 2)', 'red'))
			elif x == '15':
				mainmenu()
			else:
				print(colored('[!] You need to choose a number between 1 and 15', 'red'))

def aes():
	#### ENCRYPT ####
	print('[1] Encode a message with AES')
	print('[2] Decode a message with AES')
	print('[3] Go to main menu')
	while 1:
		choix = input('[*]>>')
		if choix == '1':
			print('[?] Type the message which will be encrypted')
			msg = input('[*]>>')
			print('[1] Custom key and IV')
			print('[2] Random key and IV')
			while 1:
				choixx = input('[*]>>')
				if choixx == '2':
					key = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for x in range(32))
					iv = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for x in range(16))
					encodage = AES.new(key, AES.MODE_CFB, iv)
					chiffre = encodage.encrypt(msg)
					print('[1] Output in Base64')
					print('[2] Output in Hex')
					while 1:
						g = input('[*]>>')
						if g == '1':
							print('[!] This is the key : ' + key)
							print('[!] This is the IV : ' + iv)
							print('[!] This is the encoded message :', base64.b64encode(chiffre).decode("utf-8"))
							print('[1] Go to the main menu')
							print('[2] Quit CryptoRusse')
							while 1:
								finalchoice = input('[*]>>')
								if finalchoice == '1':
									mainmenu()
								elif finalchoice == '2':
									stop()
								else:
									print(colored('[!] You need to choose a number (1 or 2)', 'red'))
						elif g == '2':
							print('[!] This is the key : ' + key)
							print('[!] This is the IV : ' + iv)
							print('[!] This is the encoded message :', binascii.hexlify(chiffre).decode("utf-8"))
							print('[1] Go to the main menu')
							print('[2] Quit CryptoRusse')
							while 1:
								finalchoice = input('[*]>>')
								if finalchoice == '1':
									mainmenu()
								elif finalchoice == '2':
									stop()
								else:
									print(colored('[!] You need to choose a number (1 or 2)', 'red'))
						else:
							print(colored('[!] You need to choose a number (1 or 2)', 'red'))
				elif choixx == '1':
					print('[?] Type the key which will be used in encryption (32 characters only)')
					key = input('[*]>>')
					print('[?] Type the IV that will be used in encryption (16 characters only)')
					iv = input('[*]>>')
					encodage = AES.new(key, AES.MODE_CFB, iv)
					chiffre = encodage.encrypt(msg)
					print('[?] Which output do you want')
					print('[1] Output in Base64')
					print('[2] Output in Hex')
					while 1:
						g = input('[*]>>')
						if g == '1':
							print('[!] This is the key : ' + key)
							print('[!] This is the IV : ' + iv)
							print('[!] This is the encoded message :', base64.b64encode(chiffre).decode("utf-8"))
							print('[1] Go to the main menu')
							print('[2] Quit CryptoRusse')
							while 1:
								finalchoice = input('[*]>>')
								if finalchoice == '1':
									mainmenu()
								elif finalchoice == '2':
									stop()
								else:
									print(colored('[!] You need to choose a number (1 or 2)', 'red'))
						elif g == '2':
								print('[!] This is the key : ' + key)
								print('[!] This is the IV : ' + iv)
								print('[!] This is the encoded message :', binascii.hexlify(chiffre).decode("utf-8"))
								print('[1] Go to the main menu')
								print('[2] Quit CryptoRusse')
								while 1:
									finalchoice = input('[*]>>')
									if finalchoice == '1':
										mainmenu()
									elif finalchoice == '2':
										stop()
									else:
										print(colored('[!] You need to choose a number (1 or 2)', 'red'))
						else:
							print(colored('[!] You need to choose a number (1 or 2)', 'red'))
					else:
						print(colored('[!] You need to choose a number (1 or 2)', 'red'))
						#### DECRYPT ####
		elif choix == '2':
			print('[?] Type the message which will be decrypted')
			msg = input('[*]>>')
			print('[?] Type the key which will be used in decryption (32 characters only)')
			key = input('[*]>>')
			print('[?] Type the IV which will be used in decryption (16 characters only)')
			iv = input('[*]>>')
			print('[?] What is the input format')
			print('[1] Base64 input')
			print('[2] Hex input')
			while 1:
				inputn = input('[*]>>')
				if inputn == '2':
					decryption_options = AES.new(key, AES.MODE_CFB, iv)
					decryption = decryption_options.decrypt(codecs.decode(msg, "hex"))
					print('[!] This is the key : ' + key)
					print('[!] This is the IV : ' + iv)
					print('[!] This is the decrypted message :',decryption.decode("utf-8"))
					print('[1] Go to the main menu')
					print('[2] Quit CryptoRusse')
					while 1:
						finalchoice = input('[*]>>')
						if finalchoice == '1':
							mainmenu()
						elif finalchoice == '2':
							stop()
						else:
							print(colored('[!] You need to choose a number (1 or 2)', 'red'))
				elif inputn == '1':
					decryption_options = AES.new(key, AES.MODE_CFB, iv)
					decryption = decryption_options.decrypt(base64.b64decode(msg))
					print('[!] This is the key : ' + key)
					print('[!] This is the IV : ' + iv)
					print('[!] This is the decrypted message :',decryption.decode("utf-8"))
					print('[1] Go to the main menu')
					print('[2] Quit CryptoRusse')
					while 1:
						finalchoice = input('[*]>>')
						if finalchoice == '1':
							mainmenu()
						elif finalchoice == '2':
							stop()
						else:
							print(colored('[!] You need to choose a number (1 or 2)', 'red'))
				else:
					print(colored('[!] You need to choose a number (1 or 2)', 'red'))
		elif choix == '3':
			mainmenu()
		else:
			print(colored('[!] You need to choose a number (1 or 2)', 'red'))

def base():
	print('[1] Encrypt/Decrypt text in/from Base64')
	print('[2] Encrypt/Decrypt text in/from Base32')
	print('[3] Encrypt/Decrypt text in/from Base16')
	print('[4] Encrypt/Decrypt text in/from Hex')
	print('[5] Go to main menu')
	while 1:
		cchoice = input('[*]>>')
		if cchoice == '1':
			print('[1] Encrypt text in Base64')
			print('[2] Decrypt text from Base64')
			while 1:
				basee = input('[*]>>')
				if basee == '1':
					print('[?] Type the text you want to encrypt in Base64')
					textt = input('[*]>>')
					print('[!] This is the text encoded in Base64 :', b64encode(textt.encode('utf-8')).decode('utf-8'))
					print('[1] Go to the main menu')
					print('[2] Quit CryptoRusse')
					while 1:
						finalchoice = input('[*]>>')
						if finalchoice == '1':
							mainmenu()
						elif finalchoice == '2':
							stop()
						else:
							print(colored('[!] You need to choose a number (1 or 2)', 'red'))
				elif basee == '2':
					print('[?] Type the text you want to decrypt from Base64')
					textt = input('[*]>>')
					print('[!] This is the text decoded from Base64 :', b64decode(textt.encode('utf-8')).decode('utf-8'))
					print('[1] Go to the main menu')
					print('[2] Quit CryptoRusse')
					while 1:
						finalchoice = input('[*]>>')
						if finalchoice == '1':
							mainmenu()
						elif finalchoice == '2':
							stop()
						else:
							print(colored('[!] You need to choose a number (1 or 2)', 'red'))
				else:
					print(colored('[!] You need to choose a number (1 or 2)', 'red'))
		elif cchoice == '2':
			print('[1] Encrypt text in Base32')
			print('[2] Decrypt text from Base32')
			while 1:
				basee = input('[*]>>')
				if basee == '1':
					print('[?] Type the text you want to encrypt in Base32')
					textt = input('[*]>>')
					print('[!] This is the text encoded in Base32 :', b32encode(textt.encode('utf-8')).decode('utf-8'))
					print('[1] Go to the main menu')
					print('[2] Quit CryptoRusse')
					while 1:
						finalchoice = input('[*]>>')
						if finalchoice == '1':
							mainmenu()
						elif finalchoice == '2':
							stop()
						else:
							print(colored('[!] You need to choose a number (1 or 2)', 'red'))
				elif basee == '2':
					print('[?] Type the text you want to decrypt from Base32')
					textt = input('[*]>>')
					print('[!] This is the text decoded from Base32 :', b32decode(textt.encode('utf-8')).decode('utf-8'))
					print('[1] Go to the main menu')
					print('[2] Quit CryptoRusse')
					while 1:
						finalchoice = input('[*]>>')
						if finalchoice == '1':
							mainmenu()
						elif finalchoice == '2':
							stop()
						else:
							print(colored('[!] You need to choose a number (1 or 2)', 'red'))
				else:
					print(colored('[!] You need to choose a number (1 or 2)', 'red'))
		elif cchoice == '3':
			print('[1] Encrypt text in Base16')
			print('[2] Decrypt text from Base16')
			while 1:
				basee = input('[*]>>')
				if basee == '1':
					print('[?] Type the text you want to encrypt in Base16')
					textt = input('[*]>>')
					print('[!] This is the text encoded in Base16 :', b16encode(textt.encode('utf-8')).decode('utf-8'))
					print('[1] Go to the main menu')
					print('[2] Quit CryptoRusse')
					while 1:
						finalchoice = input('[*]>>')
						if finalchoice == '1':
							mainmenu()
						elif finalchoice == '2':
							stop()
						else:
							print(colored('[!] You need to choose a number (1 or 2)', 'red'))
				elif basee == '2':
					print('[?] Type the text you want to decrypt from Base16')
					textt = input('[*]>>')
					print('[!] This is the text decoded from Base16 :', b16decode(textt.encode('utf-8')).decode('utf-8'))
					print('[1] Go to the main menu')
					print('[2] Quit CryptoRusse')
					while 1:
						finalchoice = input('[*]>>')
						if finalchoice == '1':
							mainmenu()
						elif finalchoice == '2':
							stop()
						else:
							print(colored('[!] You need to choose a number (1 or 2)', 'red'))
				else:
					print(colored('[!] You need to choose a number (1 or 2)', 'red'))
		elif cchoice == '4':
			print('[1] Encrypt text in Hex')
			print('[2] Decrypt text from Hex')
			while 1:
				basee = input('[*]>>')
				if basee == '1':
					print('[?] Type the text you want to encrypt in Hex')
					textt = input('[*]>>')
					print('[!] This is the encoded text in Hex :', codecs.encode(textt.encode('utf-8'), 'hex').decode('utf-8'))
					print('[1] Go to the main menu')
					print('[2] Quit CryptoRusse')
					while 1:
						finalchoice = input('[*]>>')
						if finalchoice == '1':
							mainmenu()
						elif finalchoice == '2':
							stop()
						else:
							print(colored('[!] You need to choose a number (1 or 2)', 'red'))
				elif basee == '2':
					print('[?] Type the text you want to decrypt from Hex')
					textt = input('[*]>>')
					print('[!] This is the decoded text from Hex :', codecs.decode(textt.encode('utf-8'), 'hex').decode('utf-8'))
					print('[1] Go to the main menu')
					print('[2] Quit CryptoRusse')
					while 1:
						finalchoice = input('[*]>>')
						if finalchoice == '1':
							mainmenu()
						elif finalchoice == '2':
							stop()
						else:
							print(colored('[!] You need to choose a number (1 or 2)', 'red'))
				else:
					print(colored('[!] You need to choose a number (1 or 2)', 'red'))
		elif cchoice == '5':
			mainmenu()
		else:
			print(colored('[!] You need to choose a number between 1 and 5', 'red'))

def mainmenu():
	try:
		if sys.platform == 'win32':
			os.system("cls")
		elif sys.platform == 'linux2':
			os.system('clear')
		print(' ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ ██████╗ ██╗   ██╗███████╗███████╗███████╗')
		print('██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗██║   ██║██╔════╝██╔════╝██╔════╝')
		print('██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║██████╔╝██║   ██║███████╗███████╗█████╗  ')
		print('██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║██╔══██╗██║   ██║╚════██║╚════██║██╔══╝  ')
		print('╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝██║  ██║╚██████╔╝███████║███████║███████╗')
		print(' ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝')
		print('[!] Script by', colored('JeSuisRusse', 'red'))
		print('[!]',colored('CTRL+C', 'red'), 'to quit CryptoRusse')
		print('[1] Encode/Decode a message with AES methode (256 bits, CFB methode)')
		print('[2] Encrypt with Hashes (MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-224, SHA3-256, SHA3-384, SHA3-512, BLAKE2b, BLAKE2s, SHAKE-128, SHAKE-256)')
		print('[3] Encrypt/Decrypt text in/from Base64, Base32, Base16, Hex')
		print('[4] Exit CryptoRusse')
		while 1:
			choixxx = input("[*]>>")
			if choixxx == '1':
				aes()
			elif choixxx == '2':
				hashes()
			elif choixxx == '3':
				base()
			elif choixxx == '4':
				stop()
			else:
				print(colored('[!] You need to choose a number (1 or 2)', 'red'))
	except KeyboardInterrupt:
		stop2()

mainmenu()
