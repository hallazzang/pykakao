pykakao
=======

pykakao is a very simple kakaotalk LOCO/HTTP API protocol wrapper for python.

#### * Wait! If you gonna use 'Your' Kakaotalk ID(not an extra ID), using this library to run a bot or else is not recommended. (because of critical problem with PC Kakaotalk's login, and I don't know why it happens exactly.)
#### 2014. 2. 26
#### * Cannot use this library anymore. :( Kakao Team changed internal logic.
#### * 더 이상 파이카카오 라이브러리를 사용하는게 불가능할 것 같습니다. :( 카카오팀이 내부적으로 로직을 바꿨습니다.

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
from pykakao import kakaotalk

kakao = kakaotalk()
if kakao.auth("EMAIL", "PASSWORD", "COMPUTER NAME", "DEVICE ID"):
    # computer name and device id are not important things. you can pass any string you want.
    print kakao.session_key
    print kakao.user_id
else:
    print "auth failed."
```

2. A Simple echoing bot

```python
from pykakao import kakaotalk

kakao = kakaotalk("SESSION KEY", "DEVICE ID", USER ID)
if kakao.login():
    while True:
        packet = kakao.translate_response()
        
        if not packet:
            print "connection closed."

        if packet["command"] == "MSG":
            if packet["body"]["chatLog"]["authorId"] != kakao.user_id:
                kakao.write(packet["body"]["chatLog"]["chatId"], packet["body"]["chatLog"]["message"])
else:
    print "login failed."
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
