# MITM-sdes
# Class: CS 4980 Cryptography
# Name: Sirena Backham

# s0 and s1 boxes
S0 = [
        [1, 0, 3, 2],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [3, 1, 3, 2]
    ]

S1 = [
        [0, 1, 2, 3],
        [2, 0, 1, 3],
        [3, 0, 1, 0],
        [2, 1, 0, 3]
    ]
    
# IP table
IP = [2, 6, 3, 1, 4, 8, 5, 7]

    # EP table
EP = [4, 1, 2, 3, 2, 3, 4, 1]

    # P4 table
P4 = [2, 4, 3, 1]

def permute(k, perm_table):
        return ''.join(k[i-1] for i in perm_table)

def f_k(data, subkey):
        # split L and R
        L, R = data[:4], data[4:]

        # do EP on R
        EPonR = permute(R, EP)

        # XOR
        xor_result = ''.join(str(int(EPonR[i]) ^ int(subkey[i])) for i in range(8))

        # get L and R
        left_xor, right_xor = xor_result[:4], xor_result[4:]

        # sbox lookup and convert to binary
        left_row = int(left_xor[0] + left_xor[3], 2)
        left_col = int(left_xor[1] + left_xor[2], 2)
        left_sbox_val = bin(S0[left_row][left_col])[2:].zfill(2)

        right_row = int(right_xor[0] + right_xor[3], 2)
        right_col = int(right_xor[1] + right_xor[2], 2)
        right_sbox_val = bin(S1[right_row][right_col])[2:].zfill(2)

        sbox_result = left_sbox_val + right_sbox_val

        # p4 table
        p4_result = permute(sbox_result, P4)

        # XOR with the left half
        xor_with_L = ''.join(str(int(L[i]) ^ int(p4_result[i])) for i in range(4))

        # return R as L and append L
        return xor_with_L + R

def left_shift(data, n):
    return data[n:] + data[:n]

def is_binary(s):
    return all(bit in ('0', '1') for bit in s)

def keyGenerator(key):
    # Check key length and binary format
    if len(key) != 10 or not is_binary(key):
        print("Sorry, you entered an invalid key.")
        exit(1)
        
    #p10 table
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]

    # left shifts
    LS_1 = [2, 4, 1, 6, 3, 9, 0, 8, 7, 5]
    LS_2 = [1, 2, 3, 4, 0, 6, 7, 8, 9, 5]

    # P8 table
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]

    # pass thru p10 table
    p10Key = ''.join(key[i - 1] for i in P10)

    # get L and R
    left = p10Key[:5]
    right = p10Key[5:]

    # shifts
    left = left_shift(left, 1)
    right = left_shift(right, 1)

    # new 
    newLR = left + right

    # pass thru p8
    key1 = ''.join(newLR[i - 1] for i in P8)

    # get key 2
    left = left_shift(left, 2)
    right = left_shift(right, 2)
    newLR = left + right
    key2 = ''.join(newLR[i - 1] for i in P8)

    return key1, key2


def sdes_encrypt(p, k) :
    # Check plaintext length and binary format
    if len(p) != 8 or not is_binary(p):
        print("Sorry, you entered an invalid plaintext.")
        exit(1)
    
    # thru IP
    permuted_p = permute(p, IP)

    # round 1 w key 1 
    round1_result = f_k(permuted_p, k[0])
    #print("R1", round1_result)

    # swap 
    left, right = round1_result[:4], round1_result[4:]
    

    # round 2 w key 2
    round2_result = f_k(right + left, k[1])
    #print("R2", round2_result)
    
    # IP Inv 
    IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]

    # thru IP Inv
    ciphertext = permute(round2_result, IP_inv)

    return ciphertext

def sdes_decrypt(ciphertext, k):
    # Inverse IP table
    IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]

    # Reverse the initial permutation
    permuted_c = permute(ciphertext, IP_inv)

    # We need to run the function fk with the keys in reverse order for decryption
    round2_result = f_k(permuted_c, k[1])
    
    # swap
    left, right = round2_result[:4], round2_result[4:]

    # Round 1 with key 1
    round1_result = f_k(left + right, k[0])

    # IP table
    IP = [2, 6, 3, 1, 4, 8, 5, 7]

    # Inverse the final permutation to get the plaintext
    plaintext = permute(round1_result, IP)

    return plaintext

def mitm_attack(plaintext, ciphertext):
    # Generate all possible keys
    possible_keys = [bin(i)[2:].zfill(10) for i in range(1024)]

    # Dictionaries to store the results
    encrypt_dict = {}
    decrypt_dict = {}

    # Counters for the number of keys searched
    encrypt_keys_searched = 0
    decrypt_keys_searched = 0

    # Generate the encrypted results for all possible keys and store in encrypt_dict
    for key in possible_keys:
        encrypt_keys_searched += 1  # Increment counter for each key tried
        subkeys = keyGenerator(key)
        encrypted = sdes_encrypt(plaintext, subkeys)
        encrypt_dict[encrypted] = key

    # Generate the decrypted results for all possible keys and store in decrypt_dict
    for key in possible_keys:
        decrypt_keys_searched += 1  # Increment counter for each key tried
        subkeys = keyGenerator(key)
        decrypted = sdes_decrypt(ciphertext, subkeys)
        decrypt_dict[decrypted] = key

    # Look for matches between the two dictionaries
    for intermediate in encrypt_dict:
        if intermediate in decrypt_dict:
            # If a match is found, return the corresponding keys and the number of keys searched
            total_keys_searched = encrypt_keys_searched + decrypt_keys_searched
            return encrypt_dict[intermediate], decrypt_dict[intermediate], total_keys_searched

    # If no match is found, return None and the number of keys searched
    total_keys_searched = encrypt_keys_searched + decrypt_keys_searched
    return None, None, total_keys_searched

# inputs
P = input("Enter your plaintext (8 bits): ")
C2 = input("Enter your ciphertext (8 bits): ")

found_key1, found_key2, keys_searched = mitm_attack(P, C2)
if found_key1 and found_key2:
    print(f"Found Key 1: {found_key1}")
    print(f"Found Key 2: {found_key2}")
    print(f"Number of keys searched: {keys_searched}")
else:
    print("No matching keys found.")
    print(f"Number of keys searched: {keys_searched}")
