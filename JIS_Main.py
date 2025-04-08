# Welcome to My JIS main!
# Author: Jacob Lyon
# Project: User Password hashing and cracking via John the Ripper.

#Libraries being utilized by Project
import bcrypt
import hashlib
import matplotlib
import os
import subprocess
import time


# Helper function that takes in the user input and hashes using the MD5,SHA-256 and Bcrypt algorithms
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




#Helper function that writes the three hashed results into three unique text files
#One for Bcrypt, one for MD5 and, one for SHA-256
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
    print(f"\nStarting Wordlist + Incremental attack on {Hash_Format}")
    total_start = time.time()
    cracked = False

    # Step 1: Wordlist attack
    try:
        print(" Running Wordlist attack")
        subprocess.run(["john", f"--wordlist={Wordlist}", f"--format={Hash_Format}", File_of_Hash],
                       check=True, timeout=timeout // 2)
        # Check if it succeeded
        result = subprocess.run(["john", "--show", f"--format={Hash_Format}", File_of_Hash],
                                capture_output=True, text=True)
        if any(':' in line for line in result.stdout.strip().splitlines()):
            cracked_phase = True
    except subprocess.TimeoutExpired:
        print("Wordlist attack timed out.")
    except subprocess.CalledProcessError:
        print("Error during wordlist attack.")

    # Step 2: Incremental only if not cracked already
    if not cracked:
        try:
            print("Running Incremental attacks")
            subprocess.run(["john", "--incremental", f"--format={Hash_Format}", File_of_Hash],
                           check=True, timeout=timeout // 2)
            result = subprocess.run(["john", "--show", f"--format={Hash_Format}", File_of_Hash],
                                    capture_output=True, text=True)
            if any(':' in line for line in result.stdout.strip().splitlines()):
                cracked_phase = "Incremental"
        except subprocess.TimeoutExpired:
            print("Incremental attack timed out.")
        except subprocess.CalledProcessError:
            print("Error during incremental attack.")

    total_end = time.time()
    total_time = total_end - total_start

    return total_time


def JtR_results(File_of_Hash,Format,Time):
    result = subprocess.run(
        ["john", "--show",f"--format={Format}", File_of_Hash],
        capture_output=True,
        text=True
    )

    lines = result.stdout.strip().splitlines()

    cracked_passwords = []

    for line in lines:
        # Skip summary lines like "1 password cracked, 0 left"
        if not line or ':' not in line:
            continue

        parts = line.split(':', 1)
        if len(parts) == 2:
            password = parts[1].strip()
            cracked_passwords.append(password)

    if cracked_passwords:
        print("\nCracked: True")
        print("Time to Crack: ", round(Time, 2), "Seconds")
        for pwd in cracked_passwords:
            print("Cracked Password:", pwd)

    else:
        print("\nCracked: False")


def main():
    print("Welcome to the Password Crack Attempt Tool! Please Input a Password-String: ")
    user_input = input()


    print("Hashing of Password will now commence!\n")
    MD5_Hash, SHA256_Hash, Bcrypt_Hash = Hashing(user_input)

    print("\n The Hashes of the password will now be saved to a file!")
    md5_file, sha_file, bcrypt_file = File_Write(MD5_Hash,SHA256_Hash,Bcrypt_Hash)

    wordlist = "/Users/jakelyon/Desktop/rockyou.txt"

    md5_time= Run_JtR(md5_file, "raw-md5", wordlist, timeout=30)
    JtR_results(md5_file,"raw-md5",md5_time)

    sha256_time = Run_JtR(sha_file, "raw-sha256", wordlist, timeout=30)
    JtR_results(sha_file,"raw-sha256",sha256_time)

    bcrypt_time = Run_JtR(bcrypt_file, "bcrypt", wordlist, timeout=30)
    JtR_results(bcrypt_file,"bcrypt",bcrypt_time)



if __name__ == "__main__":
    main()