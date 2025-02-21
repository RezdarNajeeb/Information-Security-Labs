import random

def monoalphabetic_encrypt(plaintext):
    # Define the character set we want to use (common printable characters 32-126, 161-249)
    chars = ''.join([chr(i) for i in range(32, 127)] + [chr(i) for i in range(161, 250)])
    char_list = list(chars)
    
    # Create a shuffled copy of the character list (key)
    key = char_list.copy()
    random.shuffle(key)
    
    # Encrypt the plaintext by finding each character's position and using the key
    ciphertext = ''
    for char in plaintext:
        if char in char_list:
            position = char_list.index(char)
            ciphertext += key[position]
        else:
            raise ValueError(f"Character '{char}' is not a valid ASCII character.")
    
    return ciphertext, char_list, key

# Get input from user
plaintext = input("\nEnter the plaintext: ")

# Encrypt and print results
ciphertext, char_list, key = monoalphabetic_encrypt(plaintext)
print("\nEncrypted text:", ciphertext)

def monoalphabetic_decrypt (ciphertext, key):
    plaintext = ""
    for char in ciphertext:
        plaintext += char_list[key.index(char)]
    print(f"\nDecrypted text: {plaintext}")

monoalphabetic_decrypt(ciphertext, key)

# Print the key
# print("\nSubstitution Key:")
# print("Plain\tCipher")
# print("-" * 16)
# for i in range(len(char_list)):
#     print(f"{char_list[i]}\t{key[i]}")