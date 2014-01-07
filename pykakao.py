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

import os.path
import socket
import struct
import rsa
import json
from urllib import urlencode
from urllib2 import urlopen, Request
from bson import BSON, decode_all, b
from Crypto.Cipher import AES
from binascii import hexlify, unhexlify
from PIL import Image

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

    def find_user(self, user_uuid):
        """
        find(uuid)
        : find friend with uuid

        user_uuid : user's uuid to find, type str

        session key and device uuid required
        """

        if not self.session_key or not self.device_uuid:
            "error find: session key and device uuid required"
            return None

        url = "https://fr-talk.kakao.com/wp/friends/find_by_uuid.json"

        data = {}
        data["uuid"] = user_uuid

        result = self.url_open(url, data)
        if result["status"] == 0:
            return result["member"]
        else:
            return None

    def update_friend_list(self, contacts=[], removed_contacts=[], reset_contacts=False, phone_number_type=1, token=0):
        """
        update_friend_list(contacts=[], removed_contacts=[], reset_contacts=False, phone_number_type=1, token=0)
        : update friends list with provided contacts list

        contacts : contacts list
        removed_contacts : dunno exactly
        reset_contacts : default to False, reset server side's contacts list
        phone_number_type : default to 1, dunno exactly
        token : default to 0, dunno exactly

        session key and device uuid required
        """

        if not self.session_key or not self.device_uuid:
            print "error get_friend_list: session key and device uuid required"
            return None

        url = "https://sb-talk.kakao.com/win32/friends/update.json"

        data = {}
        data["contacts"] = contacts
        data["removed_contacts"] = removed_contacts
        data["reset_contacts"] = "true" if reset_contacts else "false"
        data["phone_number_type"] = phone_number_type
        data["token"] = token
        data["type"] = "f"

        result = self.url_open(url, data)
        if result["status"] == 0:
            return result["friends"]
        else:
            return None

    def get_blocked_list(self):
        """
        get_blocked_list()
        : get blocked members list

        session key and device uuid required
        """

        if not self.session_key or not self.device_uuid:
            print "error get_blocked_list: session key and device uuid required"
            return None

        url = "https://sb-talk.kakao.com/win32/friends/blocked.json"

        result = self.url_open(url)
        if result["status"] == 0:
            return result["blockedFriends"]
        else:
            return None

    def add_friend(self, user_id):
        """
        add_friend(user_id)
        : add friend by user id

        user_id : user's id to add

        session key and device uuid required
        """

        if not self.session_key or not self.device_uuid:
            print "error add_friend: session key and device uuid required"
            return None

        url = "https://fr-talk.kakao.com/wp/friends/add.json"

        data = {}
        data["id"] = user_id

        result = self.url_open(url, data)
        if result["status"] == 0:
            return result
        else:
            return None

    def upload_image(self, path):
        """
        upload_image(image_path)
        : upload image to kakao server

        path : image file's path

        user id required
        """

        if not self.user_id:
            print "error upload_image: user id required"
            return None

        boundary = "pykakao--multipart--formdata--boundary"

        try:
            image = open(path)
            data = image.read()
        except IOError:
            print "error upload_pic: cannot open file"
            return None

        body = []

        body.append("--%s" % (boundary))
        body.append("Content-Disposition: form-data; name='user_id'")
        body.append("\r\n")
        body.append(str(self.user_id))

        body.append("--%s" % (boundary))
        body.append("Content-Disposition: form-data; name='attachment_type'")
        body.append("")
        body.append("image")

        body.append("--%s" % (boundary))
        body.append("Content-Disposition: form-data; name='attachment'; filename='%s'" % (os.path.basename(path)))
        body.append("Content-Transfer-Encoding: binary")
        body.append("Content-Length: %d" % len(data))
        body.append("")
        body.append(data)

        body.append("--%s--" % (boundary))
        body.append("")

        body = "\r\n".join(body)

        url = "http://up-m.talk.kakao.com/upload"

        headers = {}
        headers["User-Agent"] = "KakaoTalk Win32 1.0.3"
        headers["Content-Type"] = "multipart/form-data; boundary=%s" % (boundary)
        headers["Content-Length"] = len(body)

        response = urlopen(Request(url, data=body, headers=headers))

        return response.read()

    def url_open(self, url, data=None):
        """
        url_open(url, headers={}, data=None)
        : open url with user's session

        url : url to open
        data : data to send, open with method GET if data is None else POST

        session key and device uuid required
        """
        
        if not self.session_key or not self.device_uuid:
            print "error url_open: session key and device uuid required"
            return None

        headers = {}
        headers["User-Agent"] = "KakaoTalk Win32 1.0.3"
        headers["A"] = "win32/1.0.3/kr"
        headers["S"] = self.session_key + "-" + self.device_uuid
        headers["Content-Type"] = "application/x-www-form-urlencoded"

        return json.load(urlopen(Request(url, data=None if not data else urlencode(data), headers=headers)))

    def checkin(self):
        """
        checkin()
        : checkin for getting loco server address

        user id required
        """

        if not self.user_id:
            print "error checkin: user_id required for this command"
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
            print "error buy: user_id required for this command"
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
            print "error login: session key and device uuid and user id required"
            return None

        if self.s:
            self.s.close()

        result = self.checkin()
        
        host = result["body"]["host"]
        port = result["body"]["port"]

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host, port))

        data = {}
        data["opt"] = ""
        data["prtVer"] = "1.0"
        data["appVer"] = "1.5.0"
        data["os"] = "win32"
        data["lang"] = "ko"
        data["sKey"] = self.session_key
        data["duuid"] = self.device_uuid
        data["ntype"] = 3
        data["MCCMNC"] = None

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
            print "error nchatlist: connection required"
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
            print "error read: connection required"
            return None

        data = {}
        data["chatId"] = chat_id
        data["since"] = since

        self.s.sendall(self.create_loco_secure_packet("READ", data))
        
        return self.translate_response(force_reply=True)

    def write(self, chat_id, msg):
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
            print "error write: connection required"
            return None

        data = {}
        data["chatId"] = chat_id
        data["msg"] = msg
        data["type"] = 1

        self.s.sendall(self.create_loco_secure_packet("WRITE", data))
        
        return self.translate_response(force_reply=True)

    def write_image(self, chat_id, url, width=0, height=0):
        """
        write_image(chat_id, url)
        : send image to chat room

        chat_id : chat room's id
        url : image url
        width : image width
        height : image height

        connection required
        """

        if not self.s:
            print "error write_image: connection required"
            return None

        extra = []
        extra.append("'path':'%s'" % (url))
        extra.append("'width':%d" % (width))
        extra.append("'height':%d" % (height))
        extra = "{%s}" % (",".join(extra))

        data = {}
        data["chatId"] = chat_id
        data["extra"] = extra
        data["type"] = 2

        self.s.sendall(self.create_loco_secure_packet("WRITE", data))

        return self.translate_response(force_reply=True)

    def write_emoticon(self, chat_id, msg, path, name="(\uc774\ubaa8\ud2f0\ucf58)"):
        """
        write_emoticon(chat_id, msg, path, name)
        : send emoticon and message to chat room
        
        chat_id : chat room's id
        msg : message
        path : emoticon path (ex. Muzi_and_Friends = 2202001.emot_001.png ~ 2202001.emot_080.png)
        name : emoticon's name

        connection required
        """

        if not self.s:
            print "error write_emoticon: connection required"
            return None

        extra = []
        extra.append("'path':'%s'" % (path))
        extra.append("'name':'%s'" % (name))
        extra = "{%s}" % (",".join(extra))

        data = {}
        data["chatId"] = chat_id
        data["msg"] = msg
        data["extra"] = extra
        data["type"] = 12

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
            print "error cwrite: connection required"
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
            print "error leave: connection required"
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
                print "error translate_response: connection required"
                return None
            else:
                s = self.s

        result = {}
        head = s.recv(4)
        if not head:
            print "error translate_response: connection closed"

            s.close()
            s = None

            return None
        elif head == "\xFF\xFF\xFF\xFF":
            body = s.recv(18)

            result["packet_id"] = head
            result["status_code"] = body[0:2]
            result["command"] = body[2:13].replace("\x00", "")
            result["body_type"] = body[13:14]
            result["body_length"] = struct.unpack("I", body[14:18])[0]
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