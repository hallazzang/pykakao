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
    print "follow link: https://pypi.python.org/pypi/rsa/"
    exit()
try:
    from bson import BSON, decode_all, b
except ImportError, e:
    print "ImportError: %s" % (e)
    print "Did you try installing pymongo package?"
    print "follow link: https://pypi.python.org/pypi/pymongo/"
    exit()
try:
    from Crypto.Cipher import AES
except ImportError, e:
    print "ImportError: %s" % (e)
    print "Did you try installing pycrypto package?"
    print "If you use Windows, follow link: http://www.voidspace.org.uk/python/modules.shtml#pycrypto"
    print "Else, 'pip install pycrypto'"
    exit()

class kakaotalk:
    def __init__(self, session_key=None, device_uuid=None, user_id=None):
        """
        Initialize kakaotalk instance with provided informations.

        Parameters:
            session_key : KakaoTalk session key. [type str]
            device_uuid : Device's Uuid. [type str]
            user_id : Kakaotalk User Id. [type int]

        Returns:


        Remarks:
            You can pass any string to 'device_uuid' but base64-encoded string recommended.
        """

        self.session_key = session_key
        self.device_uuid = device_uuid
        self.user_id = user_id

        self.s = None

    def auth(self, email, password, comp_name, device_uuid, once=False, forced=False):
        """
        Do some steps for authenticate to getting SESSION KEY and UESR ID following way like on PC KakaoTalk.

        Parameters:
            email : KakaoTalk account's email address. [type str]
            password : KakaoTalk account's password. [type str]
            comp_name : Computer's name. [type str]
            device_uuid : Device Uuid. [type str]
            once : Temporarily authentication or not. [type bool]
            forced : Dunno exatctly. [type bool]
        Returns:
            True if succeed, else False. [type bool]

        Remarks:
            You can pass any string to 'comp_name'.
            You can pass any string to 'device_uuid' but base64-encoded string recommended.
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
        Add friend with provided User Id.

        Parameters:
            user_id : User Id of member you wish to add. [type int]

        Returns:
            Friend's information if succeed, else None. [type dict]

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
            return result["friend"]
        else:
            return None

    def upload_image(self, path):
        """
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
        Get Loco server's information(Android).

        Parameters:


        Returns:
            Loco server's information if succeed, else None. [type dict]

        Remarks:

        """

        if not self.user_id:
            print "Error checkin: User Id required."
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
        result = self.translate_response(s, force_reply=True)
        if result["body"]["status"] == 0:
            return result
        else:
            return None

    def buy(self):
        """
        Get Loco server's information(Windows Phone).

        Parameters:


        Returns:
            Loco server's information if succeed, else None. [type dict]

        Remarks:

        """

        if not self.user_id:
            print "Error buy: User Id required."
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
        result = self.translate_response(s, force_reply=True)
        if result["body"]["status"] == 0:
            return result
        else:
            return None

    def login(self):
        """
        Login to Loco server.

        Parameters:


        Returns:
            Result of command if succeed, else None. [type dict]

        Remarks:
            pykakao is using Android-way login.
        """

        if not self.session_key or not self.device_uuid or not self.user_id:
            print "Error login: Session Key and Device Uuid and User Id required."
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
        result = self.translate_response(force_reply=True)
        if result["body"]["status"] == 0:
            return result
        else:
            return None

    def ping(self):
        """
        Ping to Loco server.

        Parameters:


        Returns:
            Result of command if succeed, else None. [type dict]

        Remarks:
            If you do not use this command, maybe there are no problem.
        """

        if not self.s:
            print "Error ping: Connection required"
            return None

        data = {}
        self.s.sendall(self.create_loco_secure_packet("PING", data))
        result = self.translate_response(force_reply=True)
        if result["body"]["status"] == 0:
            return result
        else:
            return None

    def nchatlist(self, max_ids=[], chat_ids=[]):
        """
        Get new chat rooms' list.

        Parameters:
            max_ids : ??? [type list]
            chat_ids : ??? [type list]

        Returns:
            Result of command if succeed, else None. [type list]

        Remarks:

        """

        if not self.s:
            print "Error nchatlist: Connection required."
            return None
            
        data = {}
        data["maxIds"] = max_ids
        data["chatIds"] = chat_ids

        self.s.sendall(self.create_loco_secure_packet("NCHATLIST", data))
        result = self.translate_response(force_reply=True)
        if result["body"]["status"] == 0:
            return result["body"]
        else:
            return None

    def read(self, chat_id, since=0L):
        """
        Read chat room's information and messages from 'since' to latest.

        Parameters:
            chat_id : Chat room's id. [type int]
            since : Message's id that you want to read from.
                    You can get it by 'nchatlist' or 'read'(Keywords are 'logId' or 'lastLogId'). [type int]

        Returns:
            Result of command if succeed, else None. [type dict]

        Remarks:

        """

        if not self.s:
            print "Error read: Connection required."
            return None

        data = {}
        data["chatId"] = chat_id
        data["since"] = since

        self.s.sendall(self.create_loco_secure_packet("READ", data))
        result = self.translate_response(self.s, force_reply=True)
        if result["body"]["status"] == 0:
            return result
        else:
            return None

    def write(self, chat_id, msg):
        """
        Send message to chat room.

        Parameters:
            chat_id : Chat room's id. [type int]
            msg : Message that you want to send. [type str]

        Returns:
            Result of command if succeed, else None. [type dict]

        Remarks:

        """

        if not self.s:
            print "Error write: Connection required."
            return None

        data = {}
        data["chatId"] = chat_id
        data["msg"] = msg
        data["type"] = 1

        self.s.sendall(self.create_loco_secure_packet("WRITE", data))
        result = self.translate_response(self.s, force_reply=True)
        if result["body"]["status"] == 0:
            return result
        else:
            return None

    def write_image(self, chat_id, url, width=0, height=0):
        """
        Send image to chat room.

        Parameters:
            chat_id : Chat room's id. [type int]
            url : Image's url. [type str]
            width : Image's width. [type int]
            height : Image's height. [type int]

        Returns:
            Result of command if succeed, else None. [type dict]

        Remarks:
            Use 'upload_image' to upload image and get image's url.
        """

        if not self.s:
            print "Error write_image: Connection required."
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
        result = self.translate_response(self.s, force_reply=True)
        if result["body"]["status"] == 0:
            return result
        else:
            return None

    def write_emoticon(self, chat_id, msg, path, name="(\uc774\ubaa8\ud2f0\ucf58)"):
        """
        Send message to chat room with emoticon.

        Parameters:
            chat_id : Chat room's id. [type int]
            msg : Message that you want to send. [type str]
            path : Emoticon's path. [type str]
            name : Emoticon's name. [type str]

        Returns:
            Result of command if succeed, else None. [type dict]

        Remarks:
            - Emoticon's pathes
                Muzi_and_Friends : 2202001.emot_001.png ~ 2202001.emot_080.png
                Frodo_and_Friends : 2202002.emot_001.png ~ 2202002.emot_080.png
                ...
            You can pass any string to 'name', default to "(\uc774\ubaa8\ud2f0\ucf58)".
        """

        if not self.s:
            print "Error write_emoticon: Connection required."
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
        result = self.translate_response(self.s, force_reply=True)
        if result["body"]["status"] == 0:
            return result
        else:
            return None

    def cwrite(self, member_ids, msg, extra=None, pushAlert=True):
        """
        Create a chat room and send message to the chat room.

        Parameters:
            member_ids : List of members' ids who you want to invite. [type list]
            msg : Message that you want to send. [type str]

        Returns:
            Result of command if succeed, else None. [type dict]

        Remarks:
            If chat room is already exists, then it behaves like 'write'.
            You can also pass two or more member ids to 'member_ids' to create group-chat room.
        """

        if not self.s:
            print "Error cwrite: Connection required."
            return None
            
        data = {}
        data["memberIds"] = member_ids
        data["msg"] = msg
        data["extra"] = extra
        data["pushAlert"] = pushAlert

        self.s.sendall(self.create_loco_secure_packet("CWRITE", data))
        result = self.translate_response(self.s, force_reply=True)
        if result["body"]["status"] == 0:
            return result
        else:
            return None

    def leave(self, chat_id):
        """
        Leave chat room.

        Parameters:
            chat_id : Chat room's id. [type int]

        Returns:
            Result of command if succeed, else None. [type dict]

        Remarks:

        """

        if not self.s:
            print "Error leave: Connection required."
            return None
            
        data = {}
        data["chatId"] = chat_id

        self.s.sendall(self.create_loco_secure_packet("LEAVE", data))
        result = self.translate_response(self.s, force_reply=True)
        if result["body"]["status"] == 0:
            return result
        else:
            return None

    def translate_response(self, s=None, force_reply=False):
        """
        Translate response packet from Loco server.

        Parameters:
            s : Socket which is connected to Loco server. [type socket]
            force_reply : Force to return the pykakao-reply packet. [type bool]

        Returns:
            Result of command if succeed, else None. [type dict]

        Remarks:
            Result's keys are these.:
                (packet_id, status_code, command, body_type, body_length, body)
            If 'force_reply' is True, non-pykakao-reply packets will be send to 'handle_packet'.
            You can override 'handle_packet' to handle these packets.
        """

        if not s:
            if not self.s:
                print "Error translate_response: Connection required."
                return None
            else:
                s = self.s

        result = {}
        head = s.recv(4)
        if not head:
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
        Handle non-pykakao-reply packets.

        Parameters:
            packet : unhandled response packets from Loco server. [type dict]

        Returns:


        Remarks:
            You can override this function to handle non-pykakao-reply packets.
        """

        pass

    def create_loco_packet(self, command, args):        
        packet = "\xFF\xFF\xFF\xFF"
        packet += "\x00\x00"
        packet += command + "\x00" * (11 - len(command))
        packet += "\x00"

        body = BSON.encode(args)

        packet += body[:4]
        packet += body

        return packet

    def create_loco_secure_packet(self, command, args):
        enc_body = self.enc_aes(self.create_loco_packet(command, args))
        packet = struct.pack("I", len(enc_body)) + enc_body

        return packet

    def create_loco_handshake_packet(self, command, args):

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