import os

import secrets
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import random

import string

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
  try:
    decoded = b64d(token)
    salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iter, 'big')
    key = _derive_key(password.encode(), salt, iterations)
    return Fernet(key).decrypt(token)
  except InvalidToken:
    print("Incorrect master password. Could not provide user passwords.")
    return b''


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

def createPassword(chars: list, passSize: int) -> str:
  newPass = ""
  for i in range(passSize):
    value = random.randint(0, len(chars) - 1)
    newPass += chars[value]
  return newPass

def generatePassword(masterPass: str):
  website = input("Please input the website that the password belongs to: ")
  passType = input("What type of password do you want?\n1 - Only upper and lower case letters (NOT RECOMMENDED)\n2 - Alphanumeric characters (Aa1)\n3 - Alphanumeric + special characters (Aa1^)\nYour input: ")
  passSize = int(input("How big do you want your password to be? Choice: "))
  if passType == "1":
    possChars = list(string.ascii_letters)
  elif passType == "2":
    possChars = list(string.ascii_letters + string.digits)
  elif passType == "3":
    specChars = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
    possChars = list(string.ascii_letters + string.digits + specChars)
  newPassword = createPassword(possChars, passSize)
  encryptedPassword = password_encrypt(newPassword.encode(), masterPass)
  if os.stat("Passwords.txt").st_size == 0:
    newString = f'{website}:{encryptedPassword.decode()}'
  else:
    newString = f'\n{website}:{encryptedPassword.decode()}'
  passwords = open("Passwords.txt", "a")
  passwords.write(newString)
  passwords.close()
  print(f"New password added: {website}: {newPassword}")


def updateMasterPassword() -> str:
  updatedPass = input("Please input your actual master password: ")
  return updatedPass


masterPass = input("Please enter your master password: ")
userChoice = input("Password Manager Menu\n1 - View passwords\n2 - Add new password\n3 - Generate new password\n4 - Re-enter master password (if you made a misinput)\nQ - End program\nYour input: ")

while userChoice.lower() != 'q':
  if userChoice == '1':
    viewPasswords(masterPass)
  elif userChoice == '2':
    addPassword(masterPass)
  elif userChoice == '3':
    generatePassword(masterPass)
  elif userChoice == '4':
    masterPass = updateMasterPassword()
  else:
    print('Misinput. Try again!')
  userChoice = input("\nPassword Manager Menu\n1 - View passwords\n2 - Add new password\n3 - Generate new password\n4 - Re-enter master password (if you made a misinput)\nAny other key - End program\nYour input: ")

print('Thank you for using Password Manager. Good bye!')