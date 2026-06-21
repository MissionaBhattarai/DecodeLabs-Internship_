text = input("Enter text: ")
shift = 3

encrypted = ""

for char in text:
    if char.isalpha():
        if char.isupper():
            encrypted += chr((ord(char) - 65 + shift) % 26 + 65)
        else:
            encrypted += chr((ord(char) - 97 + shift) % 26 + 97)
    else:
        encrypted += char

print("Encrypted Text:", encrypted)

decrypted = ""

for char in encrypted:
    if char.isalpha():
        if char.isupper():
            decrypted += chr((ord(char) - 65 - shift) % 26 + 65)
        else:
            decrypted += chr((ord(char) - 97 - shift) % 26 + 97)
    else:
        decrypted += char

print("Decrypted Text:", decrypted)