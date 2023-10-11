import binascii

from Crypto.Hash import RIPEMD160
ripemd160 = RIPEMD160.new(data=b'hello').digest()
print("RIPEMD-160:", binascii.hexlify(ripemd160))


from Crypto.Hash import keccak
keccak256 = keccak.new(data=b'hello', digest_bits=256).digest()
print("Keccak256:", binascii.hexlify(keccak256))