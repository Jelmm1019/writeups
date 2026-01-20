test = 'SUMMERSCHOOL{AAAAAAAAAAAAAAAAAAA}'
test_enc = '83 fe 7b 1c a1 b7 8d 2e 90 30 55 13 6f 5e d3 a4 a1 5a 1f 00 cd 16 2b 1c b9 92 f7 f8 65 ce 83 94 0d'
flag_enc = '83 fe 7b 1c a1 b7 8d 2e 90 30 55 13 6f 74 c5 af a3 49 2b 04 eb 29 1a 3a cc 92 08 0b 58 df 97 88 0d'

test_bytes = bytes.fromhex(test_enc)
flag_bytes = bytes.fromhex(flag_enc)

diffs = [(f - t) for f, t in zip(flag_bytes, test_bytes)]

flag = ''.join(chr((ord(c) + d) % 256) for c, d in zip(test, diffs))

print(flag)