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
    Bcrypt_Hash = bcrypt.hashpw(user_input.encode(), bcrypt.gensalt())
    print("Result: ",Bcrypt_Hash)

    return 0




def main():
    print("Welcome to the Password Cracker! Please Input a Password-String: ")
    user_input = input()


    print("Hashing of Password will now commence!\n")
    Hashing(user_input)

    return 0

main()