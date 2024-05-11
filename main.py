import os

import secrets
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

backend = default_backend()
iterations = 100_000

def _derive_key(password: bytes, salt: bytes, iterations: int = iterations) -> bytes:
  # Derive a secret key from a given password and salt
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(), length=32, salt=salt,
    iterations=iterations, backend=backend)
  return b64e(kdf.derive(password))

def password_encrypt(message: bytes, password: str, iterations: int = iterations) -> bytes:
  salt = secrets.token_bytes(16)
  key = _derive_key(password.encode(), salt, iterations)
  return b64e(
    b'%b%b%b' % (
      salt,
      iterations.to_bytes(4, 'big'),
      b64d(Fernet(key).encrypt(message)),
    )
  )

def password_decrypt(token: bytes, password: str) -> bytes:
  decoded = b64d(token)
  salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
  iterations = int.from_bytes(iter, 'big')
  key = _derive_key(password.encode(), salt, iterations)
  return Fernet(key).decrypt(token)

def viewPasswords(masterPass: str):
  passwords = open("Passwords.txt", "r")
  passwordsArr = passwords.readlines()
  print("Passwords List:")
  for i in passwordsArr:
    webPass = i.split(":")
    print(f"{webPass[0]}: {password_decrypt(webPass[1].encode(), masterPass).decode()}")

def addPassword(masterPass: str):
  website = input("Please input the website that the password belongs to: ")
  newPassword = input("Please input the new password: ")
  encryptedPassword = password_encrypt(newPassword.encode(), masterPass)
  if os.stat("Passwords.txt").st_size == 0:
    newString = f'{website}:{encryptedPassword.decode()}'
  else:
    newString = f'\n{website}:{encryptedPassword.decode()}'
  passwords = open("Passwords.txt", "a")
  passwords.write(newString)
  passwords.close()


masterPass = input("Please enter your master password: ")
userChoice = input("Password Manager Menu\n1 - View passwords\n2 - Add new password\n3 - Generate new password\n4 - Re-enter master password (if you made a misinput)\nQ - End program\nYour input: ")

while userChoice.lower() != 'q':
  if userChoice == '1':
    viewPasswords(masterPass)
  elif userChoice == '2':
    addPassword(masterPass)
  elif userChoice == '3':
    print('12gdrg54536435')
  elif userChoice == '4':
    print('You misclicked lollll')
  else:
    print('Misinput. Try again!')
  userChoice = input("\nPassword Manager Menu\n1 - View passwords\n2 - Add new password\n3 - Generate new password\n4 - Re-enter master password (if you made a misinput)\nAny other key - End program\nYour input: ")

print('Thank you for using Password Manager. Good bye!')