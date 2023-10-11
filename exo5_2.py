import hashlib, binascii

text = 'hello'
data = text.encode("utf8")

sha256hash = hashlib.sha256(b'hello').digest()
print("SHA-256: ", binascii.hexlify(sha256hash))

sha3_256 = hashlib.sha3_256(b'hello').digest()
print("SHA3-256:", binascii.hexlify(sha3_256))

blake2s = hashlib.new('blake2s', b'hello').digest()
print("BLAKE2s: ", binascii.hexlify(blake2s))

