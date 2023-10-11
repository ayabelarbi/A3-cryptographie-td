from aes_pkcs5.algorithms.aes_cbc_pkcs5_padding import AESCBCPKCS5Padding
import secrets

key = "@NcRfUjXn2r5u8x/"
output_format = "hex"
iv = secrets.token_hex(8)
plaintext = "Text for encryption"
cipher = AESCBCPKCS5Padding(key, output_format, iv)
ciphertext = cipher.encrypt(plaintext)
print('Encrypted:', ciphertext)