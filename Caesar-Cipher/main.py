# Create a list of only printable characters
chars = list(chr(i) for i in range(256) if chr(i).isprintable())
char_map = dict(zip(chars, range(len(chars)))) # Dictionary mapping (character, index) pairs

def caesar_encrypt(plain_text, shift):
    ciphertext = []
    for char in plain_text:
        if char not in char_map:
            exit(f'Invalid Character')
        ciphertext.append(chars[(char_map[char] + shift) % len(chars)])
    return ''.join(ciphertext)

def caesar_decrypt(cipher_text, shift):
    plaintext = []
    for char in cipher_text:
        if char not in char_map:
            exit(f'Invalid Character')
        plaintext.append(chars[(char_map[char] - shift) % len(chars)])
    return ''.join(plaintext)

def caesar_attack(cipher_text):
    for i in range(len(chars)):
        if i == 0:
            continue
        decrypted_attempt = caesar_decrypt(cipher_text, i)
        print(f"Shift (K) = {i}: {decrypted_attempt}")

# Get user input
plainText = input("Enter the plaintext: ")
shiftNum = abs(int(input("Enter the shift: "))) % len(chars)

# Encrypt the plaintext and display the result
encrypted = caesar_encrypt(plainText, shiftNum)
print("Encrypted text:", encrypted)

# Decrypt the encrypted text and display the result
decrypted = caesar_decrypt(encrypted, shiftNum)
print(f"Decrypted text: {decrypted}")

# Brute force attack on the encrypted text
print(f"\nBrute Force Attack For This Encrypted Text: {encrypted}")
caesar_attack(encrypted)