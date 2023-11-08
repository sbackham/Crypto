# Extended Euclidean Algorithm
# Class: CS 4980 Cryptography
# Name: Sirena Backham

def gcdExtended(n, m):
    #n or m cannot be negative
    if n < 0 or m < 0:
        raise ValueError("Please input positive numbers only")

    #base case
    if n == 0:
        return m, 0, 1
    gcd, x1, y1 = gcdExtended(m % n, n)

    #recursion call
    x = y1-(m//n)*x1
    y = x1
    return gcd, x, y

if __name__ == "__main__":
    try:
        n = int(input("Enter the first number (n): "))
        m = int(input("Enter the second number (m): "))
        g,s,t = gcdExtended(n, m)
        print(f"gcd({n}, {m}) = {g}")
        print(f"s = {s}")
        print(f"t = {t}")

    except ValueError as e:
        print(f"Error: {e}")