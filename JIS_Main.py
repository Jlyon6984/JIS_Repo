# Welcome to My JIS main!
# Author: Jacob Lyon
# Project: User Password hashing and cracking via John the Ripper.

import hashlib
import matplotlib
import bcrypt


def Hashing(user_input):
    # This section of the function makes use of the MD5 algorithm via hashlib to hash user input
    # The result of this hash is also reported back to the user.
    print("Hashing with MD5")
    MD5_Hash = hashlib.md5(user_input.encode()).hexdigest()
    print("Result: " + MD5_Hash, "\n" )

    # This section of the function makes use of the SHA-256 algorithm via hashlib to hash user input
    # The result of this hash is also reported back to the user.
    print("Hashing with SHA-256")
    SHA256_Hash = hashlib.sha256(user_input.encode()).hexdigest()
    print("Result: " + SHA256_Hash,"\n")

    # This section of the function makes use of the Bcrypt algorithm via the Bcrypt Library to hash user
    # input The result of this hash is also reported back to the user.
    print("Hashing with Bcrypt")
    Bcrypt_Hash = bcrypt.hashpw(user_input.encode(), bcrypt.gensalt()).decode()
    print("Result: ",Bcrypt_Hash)

    return MD5_Hash,SHA256_Hash,Bcrypt_Hash

def File_Write(MD5,SHA,Bcrypt):
    file = open("Passwords.txt","w")
    list = []

    list.append(MD5 + "\n")

    list.append(SHA + "\n")

    list.append(Bcrypt + "\n")

    file.writelines(list)
    file.close()
    print("Hashes Saved to File!")




def main():
    print("Welcome to the Password Cracker! Please Input a Password-String: ")
    user_input = input()


    print("Hashing of Password will now commence!\n")
    MD5_Hash, SHA256_Hash, Bcrypt_Hash = Hashing(user_input)

    print("The Hashes of the password will now be saved to a file!")
    File_Write(SHA256_Hash,MD5_Hash,Bcrypt_Hash)

    return 0

main()