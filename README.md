pykakao
=======

pykakao is a very simple kakaotalk LOCO/HTTP protocol wrapper for python

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

2. A imple echoing bot

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
