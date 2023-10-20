# 1 Prerequisites

- AES: An encryption algorithm.

- SHA3: A hash function.

- ECB: A mode of operation.

- RSA: A signature algorithm, a key exchange algorithm, and an encryption algorithm.

- HMAC: A mechanism for message authentication using cryptographic hash functions.

- LZ: A lossless data compression algorithm.

- DH: A key exchange algorithm.

- ChaCha20-Poly1305 : is an authenticated encryption with additional data (AEAD) algorithm that combines the ChaCha20 stream cipher with the Poly1305 message authentication code.

- AES-128 refers to the size of the key used in the Advanced Encryption Standard (AES) algorithm, which is 128 bits or 16 bytes . The block size of AES is also 128 bits.

- SHA-3 means : It is the third version of SHA.
  SHA-3 is a cryptographic hash function that was selected by the National Institute of Standards and Technology (NIST) in 2012 after a public competition among non-NSA designers. It is internally different from the MD5-like structure of SHA-1 and SHA-2.
  
- 1101110001000010011000110001001001100010100110011011000110100101100110111111101100001101100100101000100110110100001010001100111 : Binary

- 6e213189314cd8d2cdfd86c944da1467 : hexadecimal

- NmUyMTMxODkzMTRjZDhkMmNkZmQ4NmM5NDRkYTE0NjcK : base64

- 146387430040258906480581650393585030247 : decimal

# 2 ECB, CBC modes illustration

encryption command for ECB encryption ``` openssl enc -aes-128-ecb -in [filename].body -out [filename].encrypted -K [encryption_key] -nosalt```

encryption command for CBC encryption ```openssl enc -aes-128-cbc -in [filename].body -out [filename].encrypted -K [encryption_key] -iv [IV] -nosalt```

encryption key generation command : ```openssl rand -hex 16```

exemple of key generated : f68f714d8f7f67c87aa389474404c46a or 041bf8549ccba08f5becfc0350367447 

<div style="display: flex; justify-content: space-between;">
  <div style="flex: 1; margin-right: 10px;">
    <img src="bitcoin.png" alt="Description de l'image 1" />
    <p>original image</p>
  </div>
  <div style="flex: 1; margin-right: 10px;">
    <img src="bitcoin-ecb.png" alt="Image cryptée en ecb" />
    <p>Crypted image with ecb</p>
  </div>
  <div style="flex: 1;">
    <img src="bitcoin-cbc.png" alt="Image cryptée en cbc" />
    <p>Crypted image with cbc</p>
  </div>
</div>


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

Same as 4.1 🥳

# 5 Hash Function with python 

SHA-256:
Hash function: hashlib.sha256() \
Output size: 256 bits or 32 bytes \
Calculation: ```hashlib.sha256(b'hello').digest()```

SHA3-256:
Hash function: hashlib.sha3_256() \
Output size: 256 bits or 32 bytes \
Calculation: ```hashlib.sha3_256(b'hello').digest()```

BLAKE2s:
Hash function: hashlib.new('blake2s') \
Output size: Variable (default is 256 bits or 32 bytes) \
Calculation: ```hashlib.new('blake2s', b'hello').digest()```

## 5.2 Example 1 & 5.3 Example 2

Output obtain with the example 1

SHA-256: b'2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'

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

RSA-2048, 2048 refers to the size of the modulus used to generate the RSA public and private key pair. The modulus is a large number that is the product of two large prime numbers. It is used to compute both the public and private keys.

The public key of RSA is made up of the modulus and a public exponent. The public exponent is a small integer that is chosen randomly and kept public. The private key of RSA is made up of the modulus and the inverse of the public exponent. The inverse of the public exponent is a large integer that is kept secret.

To encrypt a message with RSA, the sender uses the recipient's public key. To decrypt a message with RSA, the recipient uses their private key.

Therefore, when we say RSA-2048, we are referring to a RSA key pair where the modulus (n) is 2048 bits long. The actual size of the private key may be larger than the public key due to the additional values it contains. 
``` 
-----BEGIN RSA PRIVATE KEY-----
RSAPrivateKey ::= SEQUENCE {
  version           Version,
  modulus           INTEGER,  -- n
  publicExponent    INTEGER,  -- e
  privateExponent   INTEGER,  -- d
  prime1            INTEGER,  -- p
  prime2            INTEGER,  -- q
  exponent1         INTEGER,  -- d mod (p-1)
  exponent2         INTEGER,  -- d mod (q-1)
  coefficient       INTEGER,  -- (inverse of q) mod p
  otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
-----END RSA PRIVATE KEY-----
```

``` 
-----BEGIN RSA PUBLIC KEY-----
RSAPublicKey ::= SEQUENCE {
    modulus           INTEGER,  -- n
    publicExponent    INTEGER   -- e
}
-----END RSA PUBLIC KEY-----
```


We had test the size of the RSA-2048 private key using this command :

``` openssl genpkey -algorithm RSA -out test-privateKey-RSA2048.pem -pkeyopt rsa_keygen_bits:2048 ```


``` openssl rsa -in test-privateKey-RSA2048.pem -pubout -out public_key.pem```

We can see that the size of the private is larger than the size of public key. (e.g : test-public_key-RSA2048.pem ans test-privateKey-RSA2048)

# 7 Algebra

## 7.1 Content of (Z/pZ)∗ where p is prime


Implementation example for the desired function :

``` 
def get_group_elements(p):
    # Find a generator of the group (Z/pZ)*
    for g in range(2, p):
        if pow(g, p-1, p) == 1:
            break

    # Iterate over all elements in the group (Z/pZ)* using the generator
    elements = []
    for i in range(0, p):
        elements.append(str(pow(g, i, p)))

    # Output each element
    return ' '.join(elements)

print(get_group_elements(23)) 
```

Output : 
``` 1 2 4 8 16 9 18 13 3 6 12 1 2 4 8 16 9 18 13 3 6 12 1 ```

## 7.2 Basic DH

```
from random import randint

q = 509
p = 2*q+1
g = 2
u = randint(2,p-1)
v = randint(2,p-1)

U = pow(g, u, p)
V = pow(g, v, p)

Ka = pow(V, u, p)
Kb = pow(U, v, p)

print(Ka)
print(Kb)
```

Output : 
```
380
380
```

Ka est bien égal à Kb

## 7.3 Modular inverse

```int_to_bytes(n)``` :  Converts an integer into a sequence of bytes.

```gcd(a, b)``` : Calculates the greatest common divisor (GCD) of two integers a and b.

```mod_inv(a, n)``` : Calculates the modular multiplicative inverse of a modulo n.

size of p in bits : ```64``` or 8 bytes
size of q in bits : ```64``` or 8 bytes
size of c in bits : ```123``` or 16 bytes

size of d in bits : ```127``` or 16 bytes
size of n in bits : ```128``` or 16 bytes
size of m in bits : ```127``` or 16 bytes

m is an integer (int)

We get ```MySecretPassword```!
