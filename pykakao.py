# coding: utf-8

"""
pykakao - simple kakaotalk loco/http protocol wrapper for python

auth by h4lla(hallazzang@gmail.com)
2014. 1. 5 ~ 2014. 1. 6

example codes:

1. how to get session key and user id

from pykakao import kakotalk
kakao = kakaotalk()
if kakao.auth("EMAIL", "PASSWORD", "COMPUTER NAME", "DEVICE ID"):
	# computer name and device id are not important things. you can pass any string you want.
	print kakao.session_key
else:
	print "auth failed"

2. simple echo bot

from pykakao import kakaotalk
kakao = kakaotalk("SESSION KEY", "DEVICE ID", USER ID)
if kakao.login()["body"]["status"] == 0:
	while True:
		packet = kakao.translate_response()

		if packet["command"] == "MSG":
			if packet["body"]["chatLog"]["authorId"] != USER ID:
				kakao.write(packet["body"]["chatLog"]["chatId"], packet["body"]["chatLog"]["message"])
else:
	print "login failed"
"""

import socket
import struct
import rsa
import json
from urllib import urlencode
from urllib2 import urlopen, Request
from bson import BSON, decode_all, b
from Crypto.Cipher import AES
from binascii import hexlify, unhexlify

class kakaotalk:
	def __init__(self, session_key=None, device_uuid=None, user_id=None):
		self.session_key = session_key
		self.device_uuid = device_uuid
		self.user_id = user_id

		self.s = None

	def auth(self, email, password, name, device_uuid, once=False, forced=False):
		"""
		auth(email, password, name, device_uuid, once=False, forced=False)
		: auth for getting session key and user id using way like on pc version kakaotalk.

		email : kakaotalk account's e-mail address
		password : kakaotalk account's password
		name : computer name, any name can passed
		device_uuid : device uuid, any string can passed but base64-encoded-string recommended
		once : default to False, temporarily auth or not
		forced : default to False, ???
		"""

		url = "https://sb-talk.kakao.com/win32/account/login.json"

		headers = {}
		headers["User-Agent"] = "KakaoTalk Win32 1.0.3"
		headers["A"] = "win32/1.0.3/en"
		headers["Content-Type"] = "application/x-www-form-urlencoded"

		data = {}
		data["email"] = email
		data["password"] = password
		data["name"] = name
		data["device_uuid"] = device_uuid
		data["model"] = ""

		result = json.load(urlopen(Request(url, data=urlencode(data), headers=headers)))
		if result["status"] == -100:
			data["once"] = "true" if once else "false"

			result = json.load(urlopen(Request(url, data=urlencode(data), headers=headers)))
			if result["status"] == 0:
				passcode = raw_input("passcode> ")

				data["forced"] = "true" if forced else "false"
				data["passcode"] = passcode

				result = json.load(urlopen(Request(url, data=urlencode(data), headers=headers)))

		if result["status"] == 0:
			self.session_key = result["sessionKey"]
			self.device_uuid = device_uuid
			self.user_id = result["userId"]

			return True
		else:
			return False

	def checkin(self):
		"""
		checkin()
		: checkin for getting loco server address

		user id required
		"""

		if not self.user_id:
			print "error checkin : user_id required for this command"
			return None

		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(("110.76.141.20", 5228))

		data = {}
		data["useSub"] = True
		data["ntype"] = 3
		data["userId"] = self.user_id
		data["MCCMNC"] = None
		data["appVer"] = "3.8.7"
		data["os"] = "android"

		s.sendall(self.create_loco_packet("CHECKIN", data))

		return self.translate_response(s, force_reply=True)

	def buy(self):
		"""
		buy()
		: ???

		user id required
		"""

		if not self.user_id:
			print "error buy : user_id required for this command"
			return None

		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(("110.76.141.20", 5228))

		data = {}
		data["ntype"] = 3
		data["countryISO"] = "KR"
		data["userId"] = self.user_id
		data["MCCMNC"] = None
		data["appVer"] = "3.8.7"
		data["os"] = "android"
		data["voip"] = False

		s.sendall(self.create_loco_packet("BUY", data))
		response = s.recv(65536)
		s.close()

		return self.translate_response(s, force_reply=True)

	def login(self):
		"""
		login()
		: login to loco server

		session key, device uuid, user id required
		"""

		if not self.session_key or not self.device_uuid or not self.user_id:
			return None

		if self.s:
			self.s.close()

		result = self.checkin()
		
		host = result["body"]["host"]
		port = result["body"]["port"]

		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.s.connect((host, port))

		data = {}
		data[u"opt"] = u""
		data[u"prtVer"] = u"1.0"
		data[u"appVer"] = u"1.5.0"
		data[u"os"] = u"win32"
		data[u"lang"] = u"ko"
		data[u"sKey"] = self.session_key
		data[u"duuid"] = self.device_uuid
		data[u"ntype"] = 3
		data[u"MCCMNC"] = None

		self.s.sendall(self.create_loco_handshake_packet("LOGIN", data))

		return self.translate_response(force_reply=True)

	def nchatlist(self, max_ids=[], chat_ids=[]):
		"""
		nchatlist(max_ids=[], chat_ids=[])
		: get new chat rooms' list

		max_ids : ???
		chat_ids : ???

		connection required
		"""

		if not self.s:
			return None
			
		data = {}
		data["maxIds"] = max_ids
		data["chatIds"] = chat_ids

		self.s.sendall(self.create_loco_secure_packet("NCHATLIST", data))
		
		return self.translate_response(force_reply=True)

	def read(self, chat_id, since=0):
		"""
		read(chat_id, since=0)
		: dunno exactly, read chat room's information

		chat_id : chat room's id
		since : ???

		connection required
		"""

		if not self.s:
			return None

		data = {}
		data["chatId"] = chat_id
		data["since"] = since

		self.s.sendall(self.create_loco_secure_packet("READ", data))
		
		return self.translate_response(force_reply=True)

	def write(self, chat_id, msg, extra=None, type=1):
		"""
		write(chat_id, msg, extra=None, type=1)
		: send message to chat room

		chat_id : chat room's id
		msg : message
		extra : default to None, ???
		type : default to 1, ???

		connection required
		"""

		if not self.s:
			return None

		data = {}
		data["chatId"] = chat_id
		data["msg"] = msg
		data["extra"] = extra
		data["type"] = type

		self.s.sendall(self.create_loco_secure_packet("WRITE", data))
		
		return self.translate_response(force_reply=True)

	def cwrite(self, member_ids, msg, extra=None, pushAlert=True):
		"""
		cwrite(member_ids=[], msg, extra=None, pushAlert=True)
		: create chat room if chat room is not exists and send message to chat room
		  (multi-chat is possible)

		member_ids : members' ids' list, type list
		msg : message
		extra : default to None, ???
		pushAlert : default to True, enable push alert setting of chat room

		connection required
		"""

		if not self.s:
			return None
			
		data = {}
		data["memberIds"] = member_ids
		data["msg"] = msg
		data["extra"] = extra
		data["pushAlert"] = pushAlert

		self.s.sendall(self.create_loco_secure_packet("CWRITE", data))
		
		return self.translate_response(force_reply=True)

	def leave(self, chat_id):
		"""
		leave(chat_id)
		: leave chat room

		chat_id : chat room's id

		connection is required
		"""

		if not self.s:
			return None
			
		data = {}
		data["chatId"] = chat_id

		self.s.sendall(self.create_loco_secure_packet("LEAVE", data))
		
		return self.translate_response(force_reply=True)

	def translate_response(self, s=None, force_reply=False):
		"""
		translate_response(s=None, force_reply=False)
		: translate incoming loco packet

		s : default to None, socket, None if want to using default socket
		force_reply : default to False, return result of command-sent-by-pykakao only
		              (other packets will be sent to handle_packet)
		"""

		if not s:
			if not self.s:
				return None
			else:
				s = self.s

		result = {}
		head = s.recv(4)
		if head == "\xFF\xFF\xFF\xFF":
			result["packet_id"] = head
			result["status_code"] = s.recv(2)
			result["command"] = s.recv(11).replace("\x00", "")
			result["body_type"] = s.recv(1)
			result["body_length"] = struct.unpack("I", s.recv(4))[0]
			result["body"] = decode_all(s.recv(result["body_length"]))[0]

			return result
		else:
			body_length = struct.unpack("I", head)[0]
			body = self.dec_aes(s.recv(body_length))

			result["packet_id"] = body[0:4]
			result["status_code"] = body[4:6]
			result["command"] = body[6:17].replace("\x00", "")
			result["body_type"] = body[17:18]
			result["body_length"] = struct.unpack("I", body[18:22])[0]
			result["body"] = decode_all(body[22:])[0]

			if result["packet_id"] != "\xFF\xFF\xFF\xFF" and force_reply:
				self.handle_packet(result)

				return self.translate_response(s, force_reply)
			else:
				return result

	def handle_packet(self, packet):
		"""
		handle_packet(packet)
		: handling command-not-sent-by-pykakao packets

		packet : packet's informations, type dict
		"""

		pass

	def create_loco_packet(self, command, args):
		"""
		create_loco_packet(command, args)
		: create loco protocol packet

		command : command
		args : arguments for command
		"""

		packet = "\xFF\xFF\xFF\xFF"
		packet += "\x00\x00"
		packet += command + "\x00" * (11 - len(command))
		packet += "\x00"

		body = BSON.encode(args)

		packet += body[:4]
		packet += body

		return packet

	def create_loco_secure_packet(self, command, args):
		"""
		create_loco_secure_packet(command, args)
		: create loco protocol secure packet

		command : command
		args : arguments for command
		"""

		enc_body = self.enc_aes(self.create_loco_packet(command, args))
		packet = struct.pack("I", len(enc_body)) + enc_body

		return packet

	def create_loco_handshake_packet(self, command, args):
		"""
		create_loco_handshake_packet(command, args)
		: create loco protocol secure handshake packet

		command : command
		args : arguments for command
		"""

		aes_key = "\x00" * 16

		handshake = "\x80\x00\x00\x00"
		handshake += "\x01\x00\x00\x00"
		handshake += "\x01\x00\x00\x00"
		handshake += self.enc_rsa(aes_key)

		return handshake + self.create_loco_secure_packet(command, args)

	def enc_aes(self, data):
		aes_key = "\x00" * 16
		IV = "locoforever\x00\x00\x00\x00\x00"

		aes = AES.new(key=aes_key, mode=AES.MODE_CBC, IV=IV)
		padded_data = self.pkcs7_encode(data)

		return aes.encrypt(padded_data)

	def dec_aes(self, data):
		aes_key = "\x00" * 16
		IV = "locoforever\x00\x00\x00\x00\x00"

		aes = AES.new(key=aes_key, mode=AES.MODE_CBC, IV=IV)
		padded_data = aes.decrypt(data)

		return self.pkcs7_decode(padded_data)

	def enc_rsa(self, data):
		N = 0xaf0dddb4de63c066808f08b441349ac0d34c57c499b89b2640fd357e5f4783bfa7b808af199d48a37c67155d77f063ddc356ebf15157d97f5eb601edc5a104fffcc8895cf9e46a40304ae1c6e44d0bcc2359221d28f757f859feccf07c13377eec2bf6ac2cdd3d13078ab6da289a236342599f07ffc1d3ef377d3181ce24c719
		E = 3

		pub_key = rsa.PublicKey(N, E)

		return rsa.encrypt(data, pub_key)

	def pkcs7_encode(self, data):
		length = len(data)
		amount_to_pad = 16 - (length % 16)
		if amount_to_pad == 0:
			amount_to_pad = 16
		return data + unhexlify("%02x" % amount_to_pad) * amount_to_pad

	def pkcs7_decode(self, data):
		return data[:-int(hexlify(data[-1]), 16)]