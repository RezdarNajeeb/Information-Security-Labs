import random

# List of printable ASCII characters
chars = list(chr(i) for i in range(256) if chr(i).isprintable())

# Shuffle the character set to create a unique cipher mapping (key)
shuffled_key = chars.copy()
random.shuffle(shuffled_key)

# Monoalphabetic Encryption
def monoalphabetic_encrypt(plain_text, key):
    # Mapped dictionary of characters to their corresponding shuffled key
    char_to_key = dict(zip(chars, key))

    # Encrypt the text by replacing each character with its mapped value
    try:
        return ''.join(char_to_key[char] for char in plain_text)
    except KeyError as e:
        # Handle the case where an input character is not in the predefined character set
        raise ValueError(f"Character '{e.args[0]}' is not a valid ASCII character.")

# Get user input
plaintext = input("Enter the plaintext: ")

# Encrypt the plaintext and display the result
encrypted = monoalphabetic_encrypt(plaintext, shuffled_key)
print("\nEncrypted text:", encrypted)

# Monoalphabetic Decryption
def monoalphabetic_decrypt(cipher_text, key):
    # Mapped dictionary of shuffled key to their corresponding characters
    key_to_char = dict(zip(key, chars))

    # Decrypt the text by replacing each character with its original mapped value
    try:
        return ''.join(key_to_char[char] for char in cipher_text)
    except KeyError as e:
        # Handle the case where an input character is not in the predefined character set
        raise ValueError(f"Character '{e.args[0]}' is not a valid ASCII character.")

# Decrypt the encrypted text and display the result
decrypted = monoalphabetic_decrypt(encrypted, shuffled_key)
print(f"\nDecrypted text: {decrypted}")


# Print the key
# print("\nSubstitution Key:")
# print("Plain\tCipher")
# print("-" * 16)
# for i in range(len(char_list)):
#     print(f"{char_list[i]}\t{key[i]}")