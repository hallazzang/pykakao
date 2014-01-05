pykakao
=======

pykakao is a very simple kakaotalk LOCO/HTTP protocol wrapper for python.

Needs
-----

First, you need to install all the packages that pykakao imports.

List of packages
- rsa
- bson
- pycrypto

Example Codes
-------------

1. How to get session key and user id

```python
from pykakao import kakotalk

kakao = kakaotalk()
if kakao.auth("EMAIL", "PASSWORD", "COMPUTER NAME", "DEVICE ID"):
	# computer name and device id are not important things. you can pass any string you want.
	print kakao.session_key
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
			if packet["body"]["chatLog"]["authorId"] != USER ID:
				kakao.write(packet["body"]["chatLog"]["chatId"], packet["body"]["chatLog"]["message"])
else:
	print "login failed"
```

License
-------

pykakao is using MIT License.

Thanks to
---------

Cai([0x90 :: Cai's Blog](http://www.bpak.org/blog/))
- [[KakaoTalk+] LOCO 프로토콜 분석 (1)](http://www.bpak.org/blog/2012/12/kakaotalk-loco-프로토콜-분석-1/)
- [[KakaoTalk+] LOCO 프로토콜 분석 (2)](http://www.bpak.org/blog/2012/12/kakaotalk-loco-프로토콜-분석-2/)
- [[KakaoTalk+] LOCO 프로토콜 분석 (3)](http://www.bpak.org/blog/2012/12/kakaotalk-loco-프로토콜-분석-3/)
- [[KakaoTalk+] LOCO 프로토콜 분석 (4)](http://www.bpak.org/blog/2012/12/kakaotalk-loco-프로토콜-분석-4/)
- [[KakaoTalkPC] 카카오톡 PC 버전 분석 (1)](https://www.bpak.org/blog/2013/08/kakaotalkpc-카카오톡-pc-버전-분석-1/)
