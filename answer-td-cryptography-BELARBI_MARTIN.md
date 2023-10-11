# 1  Prerequisites 

AES: An encryption algorithm. 

SHA3: A hash function . 

ECB: A mode of operation. 

RSA: A signature algorithm, a key exchange algorithm, and an encryption algorithm. 

HMAC: A mechanism for message authentication using cryptographic hash functions. 

LZ: A lossless data compression algorithm. 

DH: A key exchange algorithm. 

ChaCha20-Poly1305 : is an authenticated encryption with additional data (AEAD) algorithm that combines the ChaCha20 stream cipher with the Poly1305 message authentication code. 



AES-128 refers to the size of the key used in the Advanced Encryption Standard (AES) algorithm, which is 128 bits or 16 bytes . The block size of AES is also 128 bits. 

SHA-3 means : no valid answer 

SHA-3 is a cryptographic hash function that was selected by the National Institute of Standards and Technology (NIST) in 2012 after a public competition among non-NSA designers. It is internally différente from the MD5-like structure of SHA-1 and SHA-2. It is the third version of SHA. 

 

1101110001000010011000110001001001100010100110011011000110100101100110111111101100001101100100101000100110110100001010001100111 : Binary 

6e213189314cd8d2cdfd86c944da1467 : hexadecimal 

NmUyMTMxODkzMTRjZDhkMmNkZmQ4NmM5NDRkYTE0NjcK : base64 

146387430040258906480581650393585030247 : decimal 


# 2 ECB, CBC modes illustration 

to be completed ...

# 3 Key Derivation with python

3.1 Example 1

PBKDF2 is a python class that takes 5 arguments : passphrase, salt, iterations, digestmodule and macmodule. It is define this way : 

` class PBKDF2(
    passphrase: str,
    salt: bytes,
    iterations: int = 1000,
    digestmodule: Any | ((string: ReadableBuffer = b"", *, usedforsecurity: bool = True) -> _Hash) | Module("sha") = SHA1,
    macmodule: Any | Module("hmac") = HMAC
)` 

Passphrase, salt and iterations are required arguments for PBKDF2 functions. 


3.2 Example 2 

PBKDF2_HMAC is a python function that takes 5 arguments : hash_name, paassword, salt, iterations, dklen. The required parameters are hash_name, password, salt, iterations. 

(function) def pbkdf2_hmac(
    hash_name: Any,
    password: Any,
    salt: Any,
    iterations: Any,
    dklen: Any | None = None
) -> bytes

