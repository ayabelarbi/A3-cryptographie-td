import binascii
from backports.pbkdf2 import pbkdf2_hmac
salt = binascii.unhexlify('aaef2d3f4d77ac66e9c5a6c3d8f921d1')
passwd = "s3cr3tp@ss".encode("utf8")
key = pbkdf2_hmac("sha256", passwd, salt, iterations=1000000)
print("Derived key:", binascii.hexlify(key))
