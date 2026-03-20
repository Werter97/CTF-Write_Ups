#Fortune Teller
**Category:** Cryptography
**Points:** 100

## Description
We are given "cryptographically secure" random number generator. The lead engineer assured us it was basically AES.The generator is a Linear Congruential Generator (LCG) defined as:

  x_(n+1) = (a * x_n + c) % m

where m = 4294967296 (2^32), and a and c are secret.
Intercepted outputs :
* `output_1 = 2681459949`
* `output_2 = 2681459949`
* `output_3 = 1541137174`
* `output_4 = 3272915523`

The first 2 sequence are : 
1. `x_2=(a*x_1+c)%m`
2. `x_3=(a*x_2+c)%m`

We eliminate c by subtracting (2-1) : 
`x_3-x_2=(a*(x_2-x_1))%m`

Now here x_2=x_1 Thus a can take infinitely many values.
Thus looking at eqns 2 and 3:
2. `x_3=(a*x_2+c)%m`
3. `X_4=(a*x_3+c)%m`

Now subtracting these eqns (3-2):
`x_4-x_3=(a*(x_3-x_2))%m`

Now taking the modulo inverse to get a:
`a=((x_4-x_3)*modulo_inverse((x_3-x_2)))%m` 

Once we got a , we find c by :
`c=(x_2-x_1*a)%m`

We then find x_5 :
`x_5=(a*x_4+c)%m`

x_5 is a key(4 byte repeating), we convert the int to hex and then bytes.
We take xor of this 4 byte repeating key with the ciphered text to get flag.

## Exploit
```python
x_1=2681459949
x_2=2681459949
x_3=1541137174
x_4=3272915523
m=4294967296
encrypted_msg="3cff226828ec3f743bb820352aff1b7021b81b623cff31767ad428672ef6"
mod_inv=pow(x_3-x_2,-1,m)
a=((x_4-x_3)*mod_inv)%m
c=(x_3-x_2*a)%m
x_5=(x_4*a+c)%m
full_key=hex(x_5)[2:]
key=bytes.fromhex(full_key)
cipher=bytes.fromhex(encrypted_msg)
flag=""
for i in range(len(cipher)):
    flag+=chr(cipher[i]^key[i%4])
print(flag)
