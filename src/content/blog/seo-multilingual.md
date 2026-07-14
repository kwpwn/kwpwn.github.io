---
title: "Reverse Engineering: Recovering a Flag from a Simple Checker"
description: "A repeatable approach for locating comparison logic and reconstructing an expected input from a stripped binary."
locale: "en"
publishDate: 2026-07-08
draft: false
tags:
  - reverse
  - ghidra
author: "kwpwn"
---

## Initial triage

Start with basic file information and printable strings:

```bash
file ./checker
checksec --file=./checker
strings -n 6 ./checker | less
```

The binary does not contain the flag as plain text, but it does contain the
success and failure messages. Their cross-references lead to the validation
function in Ghidra.

## Validation logic

The checker loops over the input and XORs each byte with a fixed key before
comparing it against an encoded byte array. Reversing the operation is direct:

```python
encoded = [0x32, 0x1f, 0x24, 0x24]
key = 0x55
print(bytes(value ^ key for value in encoded))
```

## Takeaway

Work backward from observable behavior. Success strings, comparison functions,
and input length checks often provide faster anchors than reading `main` from
top to bottom.
