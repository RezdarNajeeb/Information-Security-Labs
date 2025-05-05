import random


# ----------------- Key Preparation Functions -----------------

def generate_master_key():
    """Generate a random 64-bit key as a string of 0s and 1s."""
    return ''.join([str(random.randint(0, 1)) for _ in range(64)])


def remove_parity_bits(key):
    """Remove the parity bits at positions 8, 16, 24, etc."""
    parity_positions = [8, 16, 24, 32, 40, 48, 56, 64]
    # Adjust positions for 0-indexing
    adjusted_positions = [pos - 1 for pos in parity_positions]

    # Create a new key without parity bits
    key_without_parity = ''
    for i in range(len(key)):
        if i not in adjusted_positions:
            key_without_parity += key[i]

    return key_without_parity


def split_key(key):
    """Split the 56-bit key into two 28-bit halves."""
    c = key[:28]
    d = key[28:]
    return c, d


def left_rotate(bits, n):
    """Perform a left circular shift on the bits by n positions.
    n: means from n to end, :n means from start to n (n is not included)"""

    return bits[n:] + bits[:n]


def apply_pc2(c, d):
    """Apply Permutation Choice 2 to get a 48-bit subkey."""
    combined = c + d
    ignore_positions = [9, 18, 22, 25, 35, 38, 43, 54]

    # Create a list of all positions (1-indexed)
    all_positions = list(range(1, 57))

    # Remove the positions to ignore
    valid_positions = [pos for pos in all_positions if pos not in ignore_positions]

    # Shuffle the positions randomly
    random.shuffle(valid_positions)

    # Take the first 48 positions for the PC-2 table
    pc2_table = valid_positions[:48]

    # Adjust positions for 0-indexing
    pc2_adjusted = [pos - 1 for pos in pc2_table]

    # Apply permutation
    subkey = ''
    for pos in pc2_adjusted:
        subkey += combined[pos]

    return subkey


def generate_subkeys(master_key):
    """Generate 16 subkeys from the master key."""
    # Remove parity bits
    key_56bit = remove_parity_bits(master_key)

    # Split the key
    c, d = split_key(key_56bit)

    # Define rotation schedule, round 1, 2, 9, and 16 have 1 rotation, others have 2 rotations
    rotation_schedule = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    subkeys = []
    for round_num in range(16):
        # Perform rotation based on the schedule
        rotations = rotation_schedule[round_num]
        c = left_rotate(c, rotations)
        d = left_rotate(d, rotations)

        # Apply PC-2 to get the subkey for this round
        subkey = apply_pc2(c, d)
        subkeys.append(subkey)

    return subkeys


# ----------------- ASCII Conversion Functions -----------------

def ascii_to_binary(text):
    """Convert ASCII text to binary representation."""
    binary = ''
    for char in text:
        # Convert each character to 8-bit binary
        binary += format(ord(char), '08b')
    return binary


def binary_to_ascii(binary):
    """Convert binary representation back to ASCII text."""
    text = ''
    # Process 8 bits at a time
    for i in range(0, len(binary), 8):
        byte = binary[i:i + 8]
        # Convert binary to integer, then to character
        text += chr(int(byte, 2))
    return text


# ----------------- Encryption Functions -----------------

def apply_initial_permutation(message):
    """Apply the Initial Permutation (IP) to the 64-bit message."""
    ip_table = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]

    # Adjust positions for 0-indexing
    ip_adjusted = [pos - 1 for pos in ip_table]

    # Apply permutation
    permuted = ''
    for pos in ip_adjusted:
        permuted += message[pos]

    return permuted


def split_message(message):
    """Split the 64-bit message into two 32-bit halves."""
    l = message[:32]
    r = message[32:]
    return l, r


def expansion_function(r_block):
    """Expand the 32-bit R block to 48 bits using the E-box."""
    # E-box table
    e_box = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]

    # Adjust positions for 0-indexing
    e_box_adjusted = [pos - 1 for pos in e_box]

    # Apply expansion
    expanded = ''
    for pos in e_box_adjusted:
        expanded += r_block[pos]

    return expanded


def xor(bits1, bits2):
    """Perform bitwise XOR between two bit strings."""
    result = ''
    for b1, b2 in zip(bits1, bits2):
        result += '1' if b1 != b2 else '0'
    return result


def apply_sbox(bits):
    """Apply the 8 S-boxes to transform 48 bits to 32 bits."""
    # S-box tables
    s_boxes = [
        # S1
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        # S2
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        # S3
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        # S4
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        # S5
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        # S6
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        # S7
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        # S8
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]

    # Divide the 48-bit input into 8 groups of 6 bits
    bit_groups = [bits[i:i + 6] for i in range(0, 48, 6)]

    # Process each group through corresponding S-box
    output = ''
    for i, group in enumerate(bit_groups):
        # First and last bits determine the row
        row = int(group[0] + group[5], 2)
        # Middle 4 bits determine the column
        col = int(group[1:5], 2)

        # Get the value from the S-box
        value = s_boxes[i][row][col]

        # Convert to 4-bit binary and add to output
        output += format(value, '04b')

    return output


def apply_pbox(bits):
    """Apply the P-box permutation to the 32-bit input."""
    # P-box table
    p_box = [
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25
    ]

    # Adjust positions for 0-indexing
    p_box_adjusted = [pos - 1 for pos in p_box]

    # Apply permutation
    permuted = ''
    for pos in p_box_adjusted:
        permuted += bits[pos]

    return permuted


def apply_final_permutation(message):
    """Apply the Final Permutation (FP) to the 64-bit message."""
    fp_table = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    ]

    # Adjust positions for 0-indexing
    fp_adjusted = [pos - 1 for pos in fp_table]

    # Apply permutation
    permuted = ''
    for pos in fp_adjusted:
        permuted += message[pos]

    return permuted


def f_function(r_block, subkey):
    """Implement the F function of the Feistel network."""
    # 1. Expansion: Expand R to 48 bits
    expanded = expansion_function(r_block)

    # 2. Key mixing: XOR with the subkey
    mixed = xor(expanded, subkey)

    # 3. Substitution: Apply S-boxes
    substituted = apply_sbox(mixed)

    # 4. Permutation: Apply P-box
    permuted = apply_pbox(substituted)

    return permuted


def des_encrypt(message, subkeys):
    """Encrypt a 64-bit message using DES with the given subkeys."""
    # Initial permutation
    message = apply_initial_permutation(message)

    # Split into left and right halves
    left, right = split_message(message)

    # 16 rounds of the Feistel network
    for i in range(16):
        # Save the current right half
        prev_right = right

        # Apply the F function to the right half
        f_result = f_function(right, subkeys[i])

        # XOR the left half with the result of the F function
        right = xor(left, f_result)

        # The new left half is the previous right half
        left = prev_right

    # Swap the final left and right halves
    combined = right + left

    # Apply the final permutation
    ciphertext = apply_final_permutation(combined)

    return ciphertext


# ----------------- Main Function with ASCII Input -----------------

def main():
    """Main function to demonstrate DES encryption with ASCII input."""
    print("\nDES Encryption with ASCII Input")
    print("=" * 50)

    # Get 8-character input from user
    while True:
        user_input = input("\nEnter exactly 8 ASCII characters to encrypt: ")
        if len(user_input) == 8 and user_input.isprintable():
            break
        else:
            print(f"Error: Please enter exactly 8 characters. You entered {len(user_input)} characters.")

    # Convert ASCII to binary
    plaintext_binary = ascii_to_binary(user_input)
    print(f"\nInput text: {user_input}")
    print(f"Binary representation (64-bit): {plaintext_binary}")

    # Generate a master key
    master_key = generate_master_key()
    print(f"\nMaster Key (64-bit): {master_key}")

    # Generate 16 subkeys
    subkeys = generate_subkeys(master_key)
    print("\nGenerating 16 subkeys...")

    # Encrypt the message
    ciphertext_binary = des_encrypt(plaintext_binary, subkeys)
    print(f"\nCiphertext (64-bit binary): {ciphertext_binary}")

    # Display the ciphertext in ASCII format
    try:
        # Try converting binary to ASCII
        ciphertext_ascii = binary_to_ascii(ciphertext_binary)

        # Check for non-printable characters and handle them
        ciphertext_display = ''.join(
            char if char.isprintable() else '?'  # Replace non-printable characters with '?'
            for char in ciphertext_ascii
        )

        print(f"Ciphertext: {ciphertext_display}")

    except:
        # Fallback: Notify the user that non-printable characters exist
        print("Ciphertext contains non-printable characters and could not be displayed.")

    # Decrypt to verify
    decrypted_binary = des_encrypt(ciphertext_binary, subkeys[::-1])
    decrypted_ascii = binary_to_ascii(decrypted_binary)
    print(f"\nDecrypted text: {decrypted_ascii}")

    # Verify decryption
    if user_input == decrypted_ascii:
        print("\nSuccess! The decrypted message matches the original input.")
    else:
        print("\nError: The decrypted message does not match the original input.")


if __name__ == "__main__":
    main()