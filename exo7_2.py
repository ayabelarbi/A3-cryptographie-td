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