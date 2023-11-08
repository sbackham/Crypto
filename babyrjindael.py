# Baby Rijndael
# Class: CS 4980 Cryptography
# Name: Sirena Backham

S_BOX = ['a', '4', '3', 'b', '8', 'e', '2', 'c', '5', '7', '6', 'f', '0', '1', '9', 'd']

def s_box_transformation(state):
    """S-box transformation"""
    return ''.join([S_BOX[int(x, 16)] for x in state])

def swap_rows(state):
    """Swaps the bytes of the given state"""
    return state[0] + state[3] + state[2] + state[1]

def matrix_multiplication(state, t_matrix):
    # Convert the state into two bytes.
    bytes_state = [state[:2], state[2:]]
    result_bytes = []

    for byte in bytes_state:
        # Convert byte to 8-bits binary representation.
        bit_representation = bin(int(byte, 16))[2:].zfill(8)
        result_byte = []

        for row in t_matrix:
            xor_result = 0
            for t_bit, state_bit in zip(row, bit_representation):
                xor_result ^= (t_bit & int(state_bit))
            result_byte.append(xor_result)

        # Convert 8-bits result to hexadecimal representation.
        result_bytes.append(format(int(''.join(map(str, result_byte)), 2), '02x'))

    return ''.join(result_bytes)

def encrypt(key, plaintext):
    """Encrypts the plaintext using the given key"""
    # Key expansion
    w0, w1 = key[:2], key[2:]
    w2 = format(int(w0, 16) ^ int(w1[::-1], 16), '02x')
    w3 = format(int(w1, 16) ^ int(w2, 16), '02x')

    # Initial round
    state = format(int(plaintext, 16) ^ int(w0 + w1, 16), '04x')
    print(f"After initial round: {state}")

    # Define the t matrix for multiplication
    t_matrix = [
        [1, 0, 1, 0, 0, 0, 1, 1],
        [1, 1, 0, 1, 0, 0, 0, 1],
        [1, 1, 1, 0, 1, 0, 0, 0],
        [1, 1, 1, 1, 0, 1, 0, 0],
        [0, 0, 1, 1, 1, 0, 1, 0],
        [0, 0, 0, 1, 1, 1, 0, 1],
        [1, 0, 0, 0, 1, 1, 1, 0],
        [0, 1, 1, 0, 1, 0, 1, 1]
    ]

    for _ in range(3):
        state = s_box_transformation(state)
        print(f"After S-box: {state}")
        state = swap_rows(state)
        print(f"After swap rows: {state}")
        state = matrix_multiplication(state, t_matrix)
        print(f"After matrix multiplication: {state}")
        state = format(int(state, 16) ^ int(w0 + w1, 16), '04x')
        print(f"After adding key: {state}")

    # Last round (without matrix multiplication)
    state = s_box_transformation(state)
    print(f"After last S-box: {state}")
    state = swap_rows(state)
    print(f"After last swap rows: {state}")
    state = format(int(state, 16) ^ int(w0 + w1, 16), '04x')
    print(f"After last adding key: {state}")

    return state

mode = input("Enter 'e' for encryption or 'd' for decryption: ")
key = input("Enter the key as a bit string: ")
data = input("Enter the bit string to be encrypted or decrypted (just one block!): ")

if mode == 'e':
    result = encrypt(key, data)
    print(f"\nFinal Encrypted result: {result}")
