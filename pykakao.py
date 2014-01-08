#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
pykakao
=======

pykakao is a very simple kakaotalk LOCO/HTTP API protocol wrapper for python.

Installation
------------
Install it using `setup.py`.

    python setup.py install

If you are using Windows, you need to install PyCrypto manually.

To install PyCrypto manually, follow these steps.
- Download [zip archive](http://puu.sh/6bKnJ.zip).
- Unzip it in Python's `site-packages` directory(Ex. `C:\Python27\Lib\site-packages` or `/Library/Python/2.7`).

Example Codes
-------------

1. How to get session key and user id

```python
from pykakao import kakotalk

kakao = kakaotalk()
if kakao.auth("EMAIL", "PASSWORD", "COMPUTER NAME", "DEVICE ID"):
    # computer name and device id are not important things. you can pass any string you want.
    print kakao.session_key
    print kakao.user_id
else:
    print "auth failed"
```

2. A Simple echoing bot

```python
from pykakao import kakaotalk

kakao = kakaotalk("SESSION KEY", "DEVICE ID", USER ID)
if kakao.login()["body"]["status"] == 0:
    while True:
        packet = kakao.translate_response()

        if packet["command"] == "MSG":
            if packet["body"]["chatLog"]["authorId"] != kakao.user_id:
                kakao.write(packet["body"]["chatLog"]["chatId"], packet["body"]["chatLog"]["message"])
else:
    print "login failed"
```

License
-------

pykakao is following MIT License.

Thanks To
---------

Cai([0x90 :: Cai's Blog](http://www.bpak.org/blog/))
- [[KakaoTalk+] LOCO 프로토콜 분석 (1)](http://www.bpak.org/blog/2012/12/kakaotalk-loco-프로토콜-분석-1/)
- [[KakaoTalk+] LOCO 프로토콜 분석 (2)](http://www.bpak.org/blog/2012/12/kakaotalk-loco-프로토콜-분석-2/)
- [[KakaoTalk+] LOCO 프로토콜 분석 (3)](http://www.bpak.org/blog/2012/12/kakaotalk-loco-프로토콜-분석-3/)
- [[KakaoTalk+] LOCO 프로토콜 분석 (4)](http://www.bpak.org/blog/2012/12/kakaotalk-loco-프로토콜-분석-4/)
- [[KakaoTalkPC] 카카오톡 PC 버전 분석 (1)](https://www.bpak.org/blog/2013/08/kakaotalkpc-카카오톡-pc-버전-분석-1/)

"""

import os.path
import socket
import struct
import json
from urllib import urlencode
from urllib2 import urlopen, Request
from binascii import hexlify, unhexlify
try:
    import rsa
except ImportError, e:
    print "ImportError: %s" % (e)
    print "Did you try installing rsa package?"
    print "link: https://pypi.python.org/pypi/rsa/"
try:
    from bson import BSON, decode_all, b
except ImportError, e:
    print "ImportError: %s" % (e)
    print "Did you try installing pymongo package?"
    print "link: https://pypi.python.org/pypi/pymongo/"
try:
    from Crypto.Cipher import AES
except ImportError, e:
    print "ImportError: %s" % (e)
    print "Did you try installing pycrypto package?"
    print "link: https://pypi.python.org/pypi/pycrypto/"

class kakaotalk:
    def __init__(self, session_key=None, device_uuid=None, user_id=None):
        """
        kakaotalk.__init__(session_key=None, device_uuid=None, user_id=None):
            Initialize kakaotalk instance with provided informations.

        Parameters:
            session_key : Existing KakaoTalk session key. [type str]
<<<<<<< HEAD
            device_uuid : Device's Uuid, you can pass any string but base64-encoded string recommended. [type str]
=======
            device_uuid : Device's uuid, you can pass any string but base64-encoded string recommended. [type str]
>>>>>>> ed9dcc86d9c3ac190f8df720e075583f0a9a5978
            user_id : Kakaotalk User Id. [type int]
        """

        self.session_key = session_key
        self.device_uuid = device_uuid
        self.user_id = user_id

        self.s = None

    def auth(self, email, password, comp_name, device_uuid, once=False, forced=False):
        """
        kakaotalk.auth(email, password, name, device_uuid, once=False, forced=False):
            Do some steps for authenticate to getting SESSION KEY and UESR ID following way like on PC KakaoTalk.
<<<<<<< HEAD

        Parameters:
            email : KakaoTalk account's email address. [type str]
            password : KakaoTalk account's password. [type str]
            comp_name : Computer's name, you can pass any string. [type str]
            device_uuid : Device Uuid, you can pass any string but base64-encoded string recommended. [type str]
            once : Temporarily authentication or not. [type bool]
            forced : Dunno exatctly. [type bool]

=======

        Parameters:
            email : KakaoTalk account's email address. [type str]
            password : KakaoTalk account's password. [type str]
            comp_name : Computer's name, you can pass any string. [type str]
            device_uuid : Device Uuid, you can pass any string but base64-encoded string recommended. [type str]
            once : Temporarily authentication or not. [type bool]
            forced : Dunno exatctly. [type bool]

>>>>>>> ed9dcc86d9c3ac190f8df720e075583f0a9a5978
        Returns:
            True if succeed, else False. [type bool]

        Remarks:
            While authenticating, you will get Pass code on your Mobile KakaoTalk.
            Enter it when pykakao asks Pass code.
        """

        url = "https://sb-talk.kakao.com/win32/account/login.json"

        headers = {}
        headers["User-Agent"] = "KakaoTalk Win32 1.1.4"
        headers["A"] = "win32/1.1.4/ko"
        headers["Content-Type"] = "application/x-www-form-urlencoded"

        data = {}
        data["email"] = email
        data["password"] = password
        data["name"] = comp_name
        data["device_uuid"] = device_uuid
        data["model"] = ""

        result = json.load(urlopen(Request(url, data=urlencode(data), headers=headers)))
        if result["status"] == -100:
            data["once"] = "true" if once else "false"

            result = json.load(urlopen(Request(url, data=urlencode(data), headers=headers)))
            if result["status"] == 0:
                print "[*] Passcode has been sent to your mobile KakaoTalk."
                passcode = raw_input("Input Pass code > ")

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
        kakaotalk.find_user(user_uuid):
            Find user with provided User Uuid.

        Parameters:
            user_uuid : User Uuid of a member you wish to find. [type str]

        Returns:
            Member's information if succeed, else None. [type dict]

        Remarks:
            Note that User Uuid is not User Id.
            User Id is a integer, and User Uuid is a string. (Ex. "h411a" - It's me!)
        """

        if not self.session_key or not self.device_uuid:
            "Error find_user: Session Key and Device Uuid required."
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
        kakaotalk.update_friend_list(contacts=[], removed_contacts=[], reset_contacts=False, phone_number_type=1, token=0):
            Update friend list with provided informations.

        Parameters:
            contacts : List of contacts. [type list]
            removed_contacts : Dunno exactly. [type list]
            reset_contacts : Reset KakaoTalk server's contacts list or not. [type bool]
            phone_number_type : Dunno exactly, normally 1. [type int]
            token : Dunno exactly. [type int]

        Returns:
            List of friends if succeed, else None. [type list]

        Remarks:
            If you want to add friend with phone number, pass list of size 1 that includes the phone number.
            I don't know what reset_contacts parameter exactly does, so I recommend you to don't change the default parameter.
        """

        if not self.session_key or not self.device_uuid:
            print "Error update_friend_list: Session Key and Device Uuid required."
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
        kakaotalk.get_blocked_list():
            Get blocked members' list.

        Parameters:

        Returns:
            List of blocked members if succeed, else None. [type list]

        Remarks:

        """

        if not self.session_key or not self.device_uuid:
            print "Error get_blocked_list: Session Key and Device Uuid required."
            return None

        url = "https://sb-talk.kakao.com/win32/friends/blocked.json"

        result = self.url_open(url)
        if result["status"] == 0:
            return result["blockedFriends"]
        else:
            return None

    def add_friend(self, user_id):
        """
        kakao.add_friend(user_id):
            Add friend with provided User Id.

        Parameters:
            user_id : User Id of member you wish to add. [type int]
<<<<<<< HEAD

        Returns:
            ???

=======

        Returns:
            ???

>>>>>>> ed9dcc86d9c3ac190f8df720e075583f0a9a5978
        Remarks:

        """

        if not self.session_key or not self.device_uuid:
            print "Error add_friend: Session Key and Device Uuid required."
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
        kakaotalk.upload_image(path):
            Upload image to KakaoTalk server.

        Parameters:
            path : Image's path that you want to upload. [type str]

        Returns:
            The uploaded file's url if succeed, else None. [type str]

        Remarks:
            Just a path will returned as result, not completed url.
            If you want a full url, put "http://dn-m.talk.kakao.com" in front of the result.
        """

        if not self.user_id:
            print "Error upload_image: User Id required."
            return None

        boundary = "pykakao--multipart--formdata--boundary"

        try:
            image = open(path)
            data = image.read()
        except IOError:
            print "Error upload_image: Cannot open file."
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
        headers["User-Agent"] = "KakaoTalk Win32 1.1.4"
        headers["Content-Type"] = "multipart/form-data; boundary=%s" % (boundary)
        headers["Content-Length"] = len(body)

        response = urlopen(Request(url, data=body, headers=headers))

        return response.read()

    def url_open(self, url, data=None):
        """
        kakaotalk.url_open(url, data=None):
            Open url with kakaotalk instance's information.

        Parameters:
            url : Url to open. [type str]
            data : Data to send, pass None if you want "GET" method. [type str]

        Returns:
            Json-loaded object. [type ???]

        Remarks:
            Session Key and Device Uuid will be required to make a HTTP request.
        """
        
        if not self.session_key or not self.device_uuid:
            print "Error url_open: Session Key and Device Uuid required."
            return None

        headers = {}
        headers["User-Agent"] = "KakaoTalk Win32 1.1.4"
        headers["A"] = "win32/1.1.4/kr"
        headers["S"] = self.session_key + "-" + self.device_uuid
        headers["Content-Type"] = "application/x-www-form-urlencoded"

        return json.load(urlopen(Request(url, data=None if not data else urlencode(data), headers=headers)))

    def checkin(self):
        """
        checkin()
        : getting loco server address (Android)
        cf. result["body"] = {status, host, cacheExpire, csport, port, cshost}

        user id required
        """

        if not self.user_id:
            print "error checkin: user_id required for this command"
            return None

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("loco.kakao.com", 10009))

        data = {}
        data["useSub"] = True
        data["ntype"] = 3
        data["userId"] = self.user_id
        data["MCCMNC"] = None
        data["appVer"] = "4.2.2"
        data["os"] = "android"

        s.sendall(self.create_loco_packet("CHECKIN", data))

        return self.translate_response(s, force_reply=True)

    def buy(self):
        """
        buy()
        : getting loco server address (Windows Phone)
        cf. result["body"] = {status, pingItv, host, reqTimeout, cacheExpire, lazyWaitItv, port, deepSleepItv}

        user id required
        """

        if not self.user_id:
            print "error buy: user_id required for this command"
            return None

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("loco.kakao.com", 10009))

        data = {}
        data["ntype"] = 3
        data["countryISO"] = "KR"
        data["userId"] = self.user_id
        data["MCCMNC"] = None
        data["appVer"] = "2.0.0.2"
        data["os"] = "wp"
        data["voip"] = False

        s.sendall(self.create_loco_packet("BUY", data))

        return self.translate_response(s, force_reply=True)

    def login(self):
        """
        login()
        : login to loco server
        cf. result["body"] = {status, userId}

        session key, device uuid, user id required
        """

        if not self.session_key or not self.device_uuid or not self.user_id:
            print "error login: session key and device uuid and user id required"
            return None

        if self.s:
            self.s.close()

        result = self.checkin() # for Android
        # result = self.buy() # for Windows Phone
        
        host = result["body"]["host"]
        port = result["body"]["port"]

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host, port))

        data = {}
        data["opt"] = ""
        data["prtVer"] = "1.0"
        data["appVer"] = "4.2.2"
        data["os"] = "android"
        data["lang"] = "ko"
        data["sKey"] = self.session_key
        data["duuid"] = self.device_uuid
        data["ntype"] = 3
        data["MCCMNC"] = None

        self.s.sendall(self.create_loco_handshake_packet("LOGIN", data))

        return self.translate_response(force_reply=True)

    def ping(self):
        """
        ping()
        : ping to loco server
        cf. result["body"] = {status}

        connection required
        """

        if not self.s:
            print "error ping: connection required"
            return None
            
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("loco.kakao.com", 10009))

        data = {}
        self.s.sendall(self.create_loco_secure_packet("PING", data))

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

    def read(self, chat_id, since=0L):
        """
        read(chat_id, since=0L)
        : read chat room's information and each messages from 'since' to recent one

        chat_id : chat room's id
        since : message's id, you can get it from nchatlist() or read() itself (keywords are logId or lastLogId)

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

        s : default to None, type socket, None if want to using default socket
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
            encrypted_body_length = struct.unpack("I", head)[0]
            
            encrypted_body = ""
            recv_encrypted_body_length = 0
            while recv_encrypted_body_length < encrypted_body_length:
                new = s.recv(encrypted_body_length - recv_encrypted_body_length)
                encrypted_body += new
                recv_encrypted_body_length += len(new)

            total_body = self.dec_aes(encrypted_body)

            total_body_length = struct.unpack("I", total_body[18:22])[0]
            recv_total_body_length = len(total_body[22:])
            while recv_total_body_length < total_body_length:
                encrypted_body_length = struct.unpack("I", s.recv(4))[0]

                encrypted_body = ""
                recv_encrypted_body_length = 0
                while recv_encrypted_body_length < encrypted_body_length:
                    new = s.recv(encrypted_body_length - recv_encrypted_body_length)
                    encrypted_body += new
                    recv_encrypted_body_length += len(new)

                body = self.dec_aes(encrypted_body)
                total_body += body
                recv_total_body_length += len(body)

            result["packet_id"] = total_body[0:4]
            result["status_code"] = total_body[4:6]
            result["command"] = total_body[6:17].replace("\x00", "")
            result["body_type"] = total_body[17:18]
            result["body_length"] = struct.unpack("I", total_body[18:22])[0]

            result["body"] = decode_all(total_body[22:])[0]

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