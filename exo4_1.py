import pyaes, secrets, binascii
import binascii
from backports.pbkdf2 import pbkdf2_hmac

iv = secrets.randbits(256)
plaintext = "Text for encryption"

salt = binascii.unhexlify('aaef2d3f4d77ac66e9c5a6c3d8f921d1')
passwd = "s3cr3tp@ss".encode("utf8")
key = pbkdf2_hmac("sha256", passwd, salt, iterations=100000)

aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
ciphertext = aes.encrypt(plaintext)
print('Encrypted:', binascii.hexlify(ciphertext))