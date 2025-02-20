# Monoalphabetic Encryption Steps:
# 1. Read each char from the plain text
# 2. Find position of that char in ASCII
# 3. Substitute with the char at that position in the Randomized Key



# Monoaplphabetic Decryption Steps:
# The encryption steps but reversely

import random
import string

chars = list(string.ascii_letters + string.digits + string.punctuation + " ")
random.seed(1)
random_key = chars.copy()
random.shuffle(random_key)

def monoalphabetic_decrypt (cipher_text, key):
    plain_text = ""
    for char in cipher_text:
        plain_text += chars[key.index(char)]
    print(f"Plain text: {plain_text}")

monoalphabetic_decrypt(input("Enter cipher text: "), random_key)
