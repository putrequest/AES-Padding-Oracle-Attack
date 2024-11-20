# Oracle padding attack on CBC mode -- backend

This repository contains a simple endpoint that works as an oracle
telling you, if the given _Ciphertext_ and _IV_ result in a correct
PKCS#7 padding when decrypted.

Your task is to decrypt the last part of a message.

The ecryption key should be placed inside `src/key.zig` as an array like:

```zig
pub const key = [_]u8{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
```

You interact with the endpoint by sending a GET request query with
parameters `c` and `iv`, for example:

```text
http://localhost:3000/?c=1231b03277c1fb949ddfd89e7f3fc122&iv=f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
```
