# ElGamal
# Class: CS 4980 Cryptography
# Name: Sirena Backham

import random
from sympy import isprime, mod_inverse, gcd

def generate_keys(p, a):
    # pick a secret Xa (private key)
    Xa = random.randint(1, p-2)
    Ya = pow(a, Xa, p)
    # public key (p, a, Ya)
    return (Xa, (p, a, Ya))

def sign_message(m, p, a, Xa):
    while True:
        # use EEA to compute k inverse
        k = random.randint(1, p-2)
        if gcd(k, p-1) == 1:  # make sure k is relatively prime to p-1
            break
    k_inv = mod_inverse(k, p-1)
    S1 = pow(a, k, p)
    S2 = ((m - Xa * S1) * k_inv) % (p - 1)
    return (S1, S2)

def verify_signature(m, S1, S2, p, a, Ya):
    # msg verification
    if S1 <= 0 or S1 >= p:
        return False
    V1 = pow(a, m, p)
    V2 = (pow(Ya, S1, p) * pow(S1, S2, p)) % p
    # is signature valid
    return V1 == V2

def get_prime_input(prompt):
    while True:
        try:
            value = int(input(prompt))
            if isprime(value):
                return value
            else:
                print("The number you entered is not a prime. Please try again.")
        except ValueError:
            print("Invalid input. Please enter an integer.")

def menu():
    print("Select an option:")
    print("k: Key Generation")
    print("s: Sign a Message")
    print("v: Verify a Signature")
    return input("Enter your choice (k/s/v): ")

#prime
p = get_prime_input("Enter a prime number: ")

#generator
a = get_prime_input("Enter your generator 'a': ") 
private_key, public_key = generate_keys(p, a)

choice = menu()
if choice == 'k':
    # generate keys
    print(f"Private key: {private_key}, Public key: {public_key}")

elif choice == 's':
    # sign a message
    m = int(input("Enter your message (as a number): ")) 
    _, public_a, public_Ya = public_key 
    signature = sign_message(m, p, public_a, private_key)
    print(f"Signature: {signature}")

elif choice == 'v':
    # verify a signature
    m = int(input("Enter the message associated with the signature (as a number): ")) 
    S1 = int(input("Enter S1 of the signature: "))
    S2 = int(input("Enter S2 of the signature: "))
    _, public_a, public_Ya = public_key  
    validity = verify_signature(m, S1, S2, p, public_a, public_Ya)
    print(f"Signature validity: {validity}")

else:
    print("Invalid option selected.")
