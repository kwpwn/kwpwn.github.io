---
title: "Binary Exploitation Notes: Finding the Offset with Cyclic Patterns"
description: "Using a cyclic pattern to determine the exact offset before controlling a saved return address."
locale: "en"
publishDate: 2026-07-12
draft: false
tags:
  - pwn
  - pwntools
author: "kwpwn"
---

## Goal

Before building a ROP chain, we need to know how many bytes are required to
reach the saved instruction pointer.

## Generate a unique pattern

Pwntools can generate a non-repeating cyclic sequence:

```python
from pwn import *

payload = cyclic(300)
process("./chall").sendline(payload)
```

After the process crashes, inspect the overwritten value in a debugger and pass
it to `cyclic_find`:

```python
offset = cyclic_find(0x6161616c)
print(offset)
```

The returned number is the exact padding length required before the next address
in the payload.

## Takeaway

A cyclic pattern is safer and faster than guessing the offset manually. Always
confirm the architecture and endianness when copying the crash value.
