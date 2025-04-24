
#Necesary libraries for core.py functions
import hashlib, bcrypt, subprocess, os, time
from metrics import parse_metrics_line, record_result
from pathlib import Path

#Establishing variables for different file locations
WORDLIST = "/Users/jakelyon/Desktop/rockyou.txt"
JOHN_POT = Path.home() / ".john" / "john.pot"

#Function that handles user input validation, disallows an empty string to be input.
def get_valid_password():
    while True:
        password = input("Enter password to test: ").strip()
        if password:
            return password
        print("Password cannot be empty. Please try again.")

#Function that handles user time restraint input, disallows non integer and 0 input.
def get_valid_time():
    while True:
        time_input = input("Max cracking time in seconds: ").strip()
        if time_input.isdigit():
            time_value = int(time_input)
            if time_value > 0:
                return time_value
            else:
                print("Time must be greater than 0.")
        else:
            print("Please enter a valid positive integer for time.")

#Function that handles the production of hashes based on the user input.
def hash_passwords(user_password):
    return (
        hashlib.md5(user_password.encode()).hexdigest(),
        hashlib.sha256(user_password.encode()).hexdigest(),
        bcrypt.hashpw(user_password.encode(), bcrypt.gensalt()).decode()
    )

#Function that handles writing the produced hashes to unique text files for use wihth JtR
def write_hashes(md5, sha256, bcrypt):
    with open("md5.txt", "w") as MD5file: MD5file.write(md5 + "\n")
    with open("sha256.txt", "w") as SHA256file: SHA256file.write(sha256 + "\n")
    with open("bcrypt.txt", "w") as Bcryptfile: Bcryptfile.write(bcrypt + "\n")
    return "md5.txt", "sha256.txt", "bcrypt.txt"

#Helper Function that clears the stored password file maintained by JtR, This is done after each of the six runs to ensure a clean, uninfluenced run.
def clear_john_pot():
    try:
        with open(JOHN_POT, "w") as f:
            f.truncate(0)
    except FileNotFoundError:
        pass

#Main function of Core.py Handles the creation of the args variable to handle execution of JtR, Also handles timing and execution of a Run
def run_john_attacks(hash_file, fmt, max_time):
    #Code Chunk that handles arg variable creation
    for mode, label in [("wordlist", "WL"), ("incremental", "I")]:
        args = ["john", f"--format={fmt}"]
        if mode == "wordlist":
            args += [f"--wordlist={WORDLIST}"]
        else:
            args += ["--incremental"]
        args += [f"--max-run-time={max_time}", hash_file]

    #Main execution chunk, starts timer as well as runs JtR through subproccess command
        start_time = time.time()  # ← moved inside loop, before each attack
        with open("jtr_output.txt", "w") as JtRfile:
            subprocess.run(args, stdout=JtRfile, stderr=subprocess.STDOUT, text=True)
        end_time = time.time()
        elapsed_time = end_time - start_time

    #Code that handles the calling of metrics parsing for JtR runs
        with open("jtr_output.txt") as JtRfile:
            for line in JtRfile:
                if "g/s" in line:
                    parse_metrics_line(line, f"{fmt.upper()}-{label}")
                    break

    #two function calls to save results of a given run and to clear the JtR file to ensure a clear run
        record_result(hash_file, fmt, label, elapsed_time)
        clear_john_pot()

