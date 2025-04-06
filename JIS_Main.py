# Welcome to My JIS main!
# Author: Jacob Lyon
# Project: User Password hashing and cracking via John the Ripper.

import bcrypt
import hashlib
import matplotlib
import os
import subprocess
import time



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




#Helper function that writes the three hashed results to a .txt file
#File will serve as input into John the Ripper
def File_Write(MD5,SHA,Bcrypt):
    md5_file = "md5_hashes.txt"
    sha_file = "sha256_hashes.txt"
    bcrypt_file = "bcrypt_hashes.txt"

    with open(md5_file,"w") as MD5_Files:
        MD5_Files.write(MD5 + "\n")

    with open(sha_file,"w") as Sha256_Files:
        Sha256_Files.write(SHA + "\n")

    with open(bcrypt_file,"w") as Bcrypt_Files:
        Bcrypt_Files.write(Bcrypt + "\n")



    print("Hashes Saved to Files!")
    return md5_file, sha_file, bcrypt_file




def Run_JtR(File_of_Hash, Hash_Format, Wordlist, timeout=30):
    print("Attemping a crack on", Hash_Format)
    start_time = time.time()

    try:
        subprocess.run(["john", f"--wordlist={Wordlist}", f"--format={Hash_Format}",
                        File_of_Hash], check = True, timeout = timeout)
    except subprocess.TimeoutExpired:
        print("John ran longer than {timeout} seconds")

    except subprocess.CalledProcessError as e:
        print("Error Running JtR")


def JtR_results(File_of_Hash,Format):
    result = subprocess.run(
        ["john", "--show",f"--format={Format}", File_of_Hash],
        capture_output=True,
        text=True
    )
    print(result)

    cracked_output = result.stdout.strip().splitlines()

    # Check if any line contains the question mark (?)
    cracked = any('?' in line for line in cracked_output)


    if cracked:
        print("Cracked: True")
        # Extract and print the cracked password from the line (before the space and ?)
        cracked_password = next(line for line in cracked_output if '?' in line).split()[0]
        print("Cracked Password:", cracked_password)
    else:
        print("Cracked: False")



def main():
    print("Welcome to the Password Cracker! Please Input a Password-String: ")
    user_input = input()


    print("Hashing of Password will now commence!\n")
    MD5_Hash, SHA256_Hash, Bcrypt_Hash = Hashing(user_input)

    print("\n The Hashes of the password will now be saved to a file!")
    md5_file, sha_file, bcrypt_file = File_Write(MD5_Hash,SHA256_Hash,Bcrypt_Hash)

    wordlist = "/Users/jakelyon/Desktop/rockyou.txt"

    Run_JtR(md5_file, "raw-md5", wordlist, timeout=30)
    JtR_results(md5_file,"raw-md5")

    #Run_JtR(sha_file, "raw-sha256", wordlist, timeout=30)

    #Run_JtR(bcrypt_file, "bcrypt", wordlist, timeout=30)s










if __name__ == "__main__":
    main()