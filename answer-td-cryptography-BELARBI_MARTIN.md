# 1 Prerequisites

- AES: An encryption algorithm.

- SHA3: A hash function.

- ECB: A mode of operation.

- RSA: A signature algorithm, a key exchange algorithm, and an encryption algorithm.

- HMAC: A mechanism for message authentication using cryptographic hash functions.

- LZ: A lossless data compression algorithm.

- DH: A key exchange algorithm.

- ChaCha20-Poly1305 : is an authenticated encryption with additional data (AEAD) algorithm that combines the ChaCha20 stream cipher with the Poly1305 message authentication code.

AES-128 refers to the size of the key used in the Advanced Encryption Standard (AES) algorithm, which is 128 bits or 16 bytes . The block size of AES is also 128 bits.

SHA-3 means : no valid answer

SHA-3 is a cryptographic hash function that was selected by the National Institute of Standards and Technology (NIST) in 2012 after a public competition among non-NSA designers. It is internally différente from the MD5-like structure of SHA-1 and SHA-2. It is the third version of SHA.

1101110001000010011000110001001001100010100110011011000110100101100110111111101100001101100100101000100110110100001010001100111 : Binary

6e213189314cd8d2cdfd86c944da1467 : hexadecimal

NmUyMTMxODkzMTRjZDhkMmNkZmQ4NmM5NDRkYTE0NjcK : base64

146387430040258906480581650393585030247 : decimal

# 2 ECB, CBC modes illustration

encryption command for ECB encryption ``` openssl enc -aes-128-ecb -in [filename].body -out [filename].encrypted -K [encryption_key] -nosalt```

encryption command for CBC encryption ```openssl enc -aes-128-cbc -in [filename].body -out [filename].encrypted -K [encryption_key] -iv [IV] -nosalt```

encryption key generation command : ```openssl rand -hex 16```

exemple of key generated : f68f714d8f7f67c87aa389474404c46a or 041bf8549ccba08f5becfc0350367447 

# 3 Key Derivation with python

## 3.1 Example 1

PBKDF2 is a python class that takes 5 arguments : passphrase, salt, iterations, digestmodule and macmodule. It is define this way :

```
class PBKDF2 (
    passphrase: str,
    salt: bytes,
    iterations: int = 1000,
    digestmodule: Any | ((string: ReadableBuffer = b"", *, usedforsecurity: bool = True) -> _Hash) | Module("sha") = SHA1,
    macmodule: Any | Module("hmac") = HMAC
) 
 ```

Passphrase, salt and iterations are required arguments for PBKDF2 functions.

## 3.2 Example 2

PBKDF2_HMAC is a python function that takes 5 arguments : hash_name, paassword, salt, iterations, dklen. The required parameters are hash_name, password, salt, iterations.

```
def pbkdf2_hmac(
    hash_name: Any,
    password: Any,
    salt: Any,
    iterations: Any,
    dklen: Any | None = None
) -> bytes 
```

# 4 Symmetric Encryption
## 4.1 Example 1
An encryption algorithm is a mathematical procedure used to convert plain text into ciphertext, making it unreadable to unauthorized individuals. It ensures the confidentiality and integrity of data by scrambling the information using a specific algorithm and a secret key.

The key size refers to the length of the key used in the encryption algorithm. It determines the strength of the encryption and the number of possible keys that can be used. Generally, a larger key size implies stronger encryption and increased security.

A mode of operation is a technique used to apply the encryption algorithm to encrypt or decrypt data in blocks or streams. It defines how multiple blocks of data are processed to achieve confidentiality and data integrity. Common modes of operation include Electronic Codebook (ECB), Cipher Block Chaining (CBC), Counter (CTR), and Galois/Counter Mode (GCM), among others.

The size of the output is 256 bits(bits), so 32 bytes (octets).

## 4.2 Example 2

Same as 4.1

# 5 Hash Function with python 

Hash function: hashlib.sha256()
Output size: 256 bits or 32 bytes
Calculation: hashlib.sha256(b'hello').digest()
SHA3-256:

Hash function: hashlib.sha3_256()
Output size: 256 bits or 32 bytes
Calculation: ``hashlib.sha3_256(b'hello').digest()
BLAKE2s:

Hash function: hashlib.new('blake2s')
Output size: Variable (default is 256 bits or 32 bytes)
Calculation: ```hashlib.new('blake2s', b'hello').digest()```

## 5.2 Example 1 & 5.3 Example 2

Output obtain with the example 1

SHA-256:
b'2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'

SHA3-256: b'3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392'

BLAKE2s:  b'19213bacc58dee6dbde3ceb9a47cbb330b3d86f8cca8997eb00be456f140ca25'

Output obtain with the example 2

SHA-256:  b'2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
SHA3-256: b'3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392'
BLAKE2s:  b'19213bacc58dee6dbde3ceb9a47cbb330b3d86f8cca8997eb00be456f140ca25'

## 5.4 Example 3

RIPEMD-160 produces a hash value with an output size of 160 bits or 20 bytes.
Keccak256 (SHA3-256) produces a hash value with an output size of 256 bits or 32 bytes.

Keccak256 and SHA3-256 are not exactly equivalent, although they are closely related. Keccak is a cryptographic sponge construction, and SHA3 is the winning algorithm of the NIST hash function competition, which is based on the Keccak construction. SHA3-256 is one specific variant of the Keccak family, which produces a 256-bit hash output. While they share similarities, they are not interchangeable in all contexts.

# 6 Prerequisites, again
- DSA: Signature algorithm

- Blake2s: Hash function

- CTR: Mode of operation

- ECDH: Key exchange algorithm

- curve25519: Elliptic curve used in cryptography

RSA-2048, both the public and private keys have a size of 2048 bits. The key size determines the level of security provided by the RSA encryption scheme, with larger key sizes generally offering stronger security against brute-force attacks and other cryptographic attacks.
