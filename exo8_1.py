import sympy

# Generate two prime numbers
p = sympy.randprime(0,1024)
q = sympy.randprime(0,1024)
print("p =",p," q :", q)
# Compute the modulus
n = p * q
print("n =", n)

# Compute Euler's totient function
phi_n = (p - 1) * (q - 1)
print("phi_n", phi_n)

# Choose a number e that is relatively prime to phi_n
e = sympy.randprime(0,phi_n)
print("e =", e)

# Ensure e and phi_n are coprime
assert sympy.gcd(e, phi_n) == 1

print("Ensure e and phi_n are coprime :", sympy.gcd(e, phi_n) == 1)


# Compute the private key
d = sympy.mod_inverse(e, phi_n)
print("d =", d)

# Ensure de ≡ 1 mod φ(n)
assert (d * e) % phi_n == 1
print("Ensure de ≡ 1 mod φ(n): ",(d * e) % phi_n == 1)