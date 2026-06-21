password = input("Enter your password: ")

length = len(password) >= 8
upper = any(char.isupper() for char in password)
digit = any(char.isdigit() for char in password)
special = any(not char.isalnum() for char in password)

score = sum([length, upper, digit, special])

if score <= 2:
    print(" It is Weak Password")
elif score == 3:
    print("It is Medium Password")
else:
    print("It is Strong Password")