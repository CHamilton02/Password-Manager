import os
import secrets
import random
import tkinter
import string
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def main():
  window = tkinter.Tk()
  window.title('Master Password')
  title = tkinter.Label(window, text='Password Manager', font=('Arial', 18, 'bold'), fg='orange')
  title.pack()
  frame = tkinter.Frame(window)
  frame.pack()
  label = tkinter.Label(frame, text='Master Password: ', font=('Arial', 14), fg='orange')
  label.grid(row=0, column=0)
  entry = tkinter.Entry(frame)
  entry.grid(row=0, column=1)
  button = tkinter.Button(frame, text='Submit', font=('Arial', 10), bg='orange', fg='white', command=lambda: mainDisplay(entry.get(), window))
  button.grid(row=0, column=2, padx=10)
  window.minsize(600, 100)
  window.mainloop()


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
  passwordList = ""
  for i in passwordsArr:
    webPass = i.split(":")
    if password_decrypt(webPass[1].encode(), masterPass) == b'':
      break
    passwordList += f"{webPass[0]}: {password_decrypt(webPass[1].encode(), masterPass).decode()}\n"
  viewPasswords = tkinter.Tk()
  if len(passwordList) == 0:
    passwordList = "Error: Wrong master password entered or no passwords currently exist."
  header = tkinter.Label(viewPasswords, text="Passwords List:", font=('Arial', 14), bg='orange',fg='white')
  header.pack()
  message = tkinter.Label(viewPasswords, text=passwordList, font=('Arial', 14), fg='orange')
  message.pack()
  viewPasswords.mainloop()

def requestPassword(masterPass: str):
  addPassWindow = tkinter.Tk()
  addPassWindow.title('Add Password')
  frame = tkinter.Frame(addPassWindow)
  frame.pack()
  label = tkinter.Label(frame, text='Input website: ', font=('Arial', 14), fg='orange')
  label.grid(row=0, column=0, sticky='w')
  websiteEntry = tkinter.Entry(frame)
  websiteEntry.grid(row=0, column=1)
  label = tkinter.Label(frame, text='Input password: ', font=('Arial', 14), fg='orange')
  label.grid(row=1, column=0, sticky='w')
  passwordEntry = tkinter.Entry(frame)
  passwordEntry.grid(row=1, column=1)
  submit = tkinter.Button(addPassWindow, text='Submit', height=1, width=10, font=('Arial', 14), bg='orange', fg='white', command=lambda: addPassword(addPassWindow, websiteEntry.get(), passwordEntry.get(), masterPass))
  submit.pack()
  addPassWindow.minsize(300, 100)
  addPassWindow.mainloop()

def addPassword(window, website, password, masterPass):
  window.destroy()
  encryptedPassword = password_encrypt(password.encode(), masterPass)
  if os.stat("Passwords.txt").st_size == 0:
    newString = f'{website}:{encryptedPassword.decode()}'
  else:
    newString = f'\n{website}:{encryptedPassword.decode()}'
  passwords = open("Passwords.txt", "a")
  passwords.write(newString)
  passwords.close()
  successMessage = tkinter.Tk()
  successMessage.title('Success!')
  label = tkinter.Label(successMessage, text=f'{website}: {password} added to the list.', font=('Arial', 14), fg='orange')
  label.pack()
  successMessage.minsize(500, 50)
  successMessage.mainloop()

def createPassword(chars: list, passSize: int) -> str:
  newPass = ""
  for i in range(passSize):
    value = random.randint(0, len(chars) - 1)
    newPass += chars[value]
  return newPass

def requestNewPassCriteria(masterPass: str):
  upperLower = tkinter.IntVar()
  alphaNumer = tkinter.IntVar()
  alphaSpec = tkinter.IntVar()
  genPassWindow = tkinter.Tk()
  genPassWindow.title('Generate Password')
  frame = tkinter.Frame(genPassWindow)
  frame.pack()
  label = tkinter.Label(frame, text='Input website: ', font=('Arial', 14), fg='orange')
  label.grid(row=0, column=0)
  websiteEntry = tkinter.Entry(frame)
  websiteEntry.grid(row=0, column=1)
  label = tkinter.Label(frame, text='Type of password:', font=('Arial', 14), fg='orange')
  label.grid(row=1, column=0)
  for (title, location, var) in (('Only upper and lower case letters (NOT RECOMMENDED)', 2, upperLower), ('Alphanumeric characters (Aa1)', 3, alphaNumer), ('Alphanumeric + special characters (Aa1^)', 4, alphaSpec)):
    check = tkinter.Checkbutton(frame, text=title, variable=var)
    check.grid(row=location, column=0, sticky='w')
  label = tkinter.Label(frame, text='Password character size: ', font=('Arial', 14), fg='orange')
  label.grid(row=5, column=0)
  sizeEntry = tkinter.Entry(frame)
  sizeEntry.grid(row=5, column=1)
  submit = tkinter.Button(genPassWindow, text='Submit', height=2, width=22, font=('Arial', 14), bg='orange', fg='white', command=lambda: generatePassword(genPassWindow, websiteEntry.get(), upperLower, alphaNumer, alphaSpec, sizeEntry.get(), masterPass))
  submit.pack()
  genPassWindow.minsize(500, 250)
  genPassWindow.mainloop()
  

def generatePassword(window, website, upperLower, alphaNumer, alphaSpec, size, masterPass):
  window.destroy()
  if upperLower:
    possChars = list(string.ascii_letters)
  elif alphaNumer:
    possChars = list(string.ascii_letters + string.digits)
  elif alphaSpec:
    specChars = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
    possChars = list(string.ascii_letters + string.digits + specChars)
  newPassword = createPassword(possChars, int(size))
  encryptedPassword = password_encrypt(newPassword.encode(), masterPass)
  if os.stat("Passwords.txt").st_size == 0:
    newString = f'{website}:{encryptedPassword.decode()}'
  else:
    newString = f'\n{website}:{encryptedPassword.decode()}'
  passwords = open("Passwords.txt", "a")
  passwords.write(newString)
  passwords.close()
  successMessage = tkinter.Tk()
  successMessage.title('Success!')
  label = tkinter.Label(successMessage, text=f'{website}: {newPassword} added to the list.', font=('Arial', 14), fg='orange')
  label.pack()
  successMessage.minsize(500, 50)
  successMessage.mainloop()

def updateMasterPassword(oldWindow) -> str:
  oldWindow.destroy()
  main()

def mainDisplay(masterPass, oldWindow):
  oldWindow.destroy()
  window = tkinter.Tk()
  if len(masterPass.strip()) == 0:
    window.title('Error: Missing Master Password')
    title = tkinter.Label(window, text='Password Manager', font=('Arial', 18, 'bold'), fg='orange')
    title.pack()
    errorMessage = tkinter.Label(window, text='ERROR! No master password entered. Please try again.', font=('Arial', 14, 'bold'), fg='red')
    errorMessage.pack()
    main()
  else:
    window.title('Password Manager')
    title = tkinter.Label(window, text='Password Manager', font=('Arial', 18, 'bold'), fg='orange')
    title.pack()
    frame = tkinter.Frame(window)
    frame.pack()
    option1 = tkinter.Button(frame, text="View Passwords", height=2, width=22, font=('Arial', 14), bg='orange', fg='white', command=lambda: viewPasswords(masterPass))
    option1.grid(row=0, column=0, padx=10, pady=10)
    option2 = tkinter.Button(frame, text="Add New Password", height=2, width=22, font=('Arial', 14), bg='orange', fg='white', command=lambda: requestPassword(masterPass))
    option2.grid(row=1, column=0)
    option3 = tkinter.Button(frame, text="Generate New Password", height=2, width=22, font=('Arial', 14), bg='orange', fg='white', command=lambda: requestNewPassCriteria(masterPass))
    option3.grid(row=0, column=1)
    option4 = tkinter.Button(frame, text="Re-enter Master Password", height=2, width=22, font=('Arial', 14), bg='orange', fg='white', command=lambda: updateMasterPassword(window))
    option4.grid(row=1, column=1)

  window.minsize(600, 300)
  window.mainloop()

if __name__ == "__main__":
  main()