import pbkdf2, binascii, os
# Derive a 256-bit AES encryption key from the password

password = "s3cr3tp@ss"
salt = os.urandom(16) # Define the salt variable

key = pbkdf2.PBKDF2(password, salt).read(32)
print('AES encryption key:', binascii.hexlify(key))