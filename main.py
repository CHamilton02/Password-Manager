import secrets
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from crpytography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

password = input("Please enter your master password: ")
userChoice = input("Password Manager Menu\n1 - View passwords\n2 - Add new password\n3 - Generate new password\n4 - Re-enter master password (if you made a misinput)\nQ - End program\nYour input: ")

while userChoice.lower() != 'q':
  if userChoice == '1':
    print('Passwords!!!')
  elif userChoice == '2':
    print('New password!')
  elif userChoice == '3':
    print('12gdrg54536435')
  elif userChoice == '4':
    print('You misclicked lollll')
  else:
    print('Misinput. Try again!')
  userChoice = input("Password Manager Menu\n1 - View passwords\n2 - Add new password\n3 - Generate new password\n4 - Re-enter master password (if you made a misinput)\nAny other key - End program\nYour input: ")

print('Thank you for using Password Manager. Good bye!')

