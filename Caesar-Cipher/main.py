# Create a list of only printable characters
chars = list(chr(i) for i in range(256) if chr(i).isprintable())

def caesar_encrypt(plain_text, shift):
    ciphertext = ""
    for char in plain_text:
        if char not in chars:
            exit(f'Invalid Character')
        position = chars.index(char)
        ciphertext += chars[(position + shift) % len(chars)]
    return ciphertext

def caesar_decrypt(cipher_text, shift):
    plaintext = ""
    for char in cipher_text:
        if char not in chars:
            exit(f'Invalid Character')
        position = chars.index(char)
        plaintext += chars[(position - shift) % len(chars)]
    return plaintext

def caesar_attack(cipher_text):
    for i in range(1, len(chars)):
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