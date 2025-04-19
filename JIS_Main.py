# Welcome to My JIS main!
# Author: Jacob Lyon
# Project: User Password hashing and cracking via John the Ripper.
from matplotlib import pyplot as plt


# Global dictionary to store performance metrics
performance_metrics = {
    "RAW-MD5-WL": {"g_s": 0, "p_s": 0, "c_s": 0},
    "RAW-MD5-I": {"g_s": 0, "p_s": 0, "c_s": 0},
    "RAW-SHA256-WL": {"g_s": 0, "p_s": 0, "c_s": 0},
    "RAW-SHA256-I": {"g_s": 0, "p_s": 0, "c_s": 0},
    "BCRYPT-WL": {"g_s": 0, "p_s": 0, "c_s": 0},
    "BCRYPT-I": {"g_s": 0, "p_s": 0, "c_s": 0}
}
summary_results = []




#Libraries being utilized by Project
import bcrypt
import hashlib
import os
import subprocess
import time
import re
import numpy as np
from matplotlib import pyplot as plt

wordlist = "/Users/jakelyon/Desktop/rockyou.txt"
JOHN_POT_PATH = os.path.expanduser("~/.john/john.pot")

def store_metrics(attack_type, g_s, p_s, c_s):
    performance_metrics[attack_type]["g_s"] = g_s
    performance_metrics[attack_type]["p_s"] = p_s
    performance_metrics[attack_type]["c_s"] = c_s


# Helper function that takes in the user input and hashes using the MD5,SHA-256 and Bcrypt algorithms
def hashing(user_input):
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
    #Preperation of Variables for file writing
    md5_file = "md5_hashes.txt"
    sha_file = "sha256_hashes.txt"
    bcrypt_file = "bcrypt_hashes.txt"

#same logic called for each algorithm to be written to a file.
    with open(md5_file,"w") as MD5_Files:
        MD5_Files.write(MD5 + "\n")

    with open(sha_file,"w") as Sha256_Files:
        Sha256_Files.write(SHA + "\n")

    with open(bcrypt_file,"w") as Bcrypt_Files:
        Bcrypt_Files.write(Bcrypt + "\n")


#returns the files for use in other functions.
    print("Hashes Saved to Files!")
    return md5_file, sha_file, bcrypt_file







#helper functions that runs John the Ripper for the various hashing algorithms

def Run_JtR_wordlist(File_of_Hash, Hash_Format, Wordlist,run_time):
    print(f"\nStarting crack on {Hash_Format}")
    total_start = time.time()

    try:
        print("Running Wordlist attack")
        # Redirect stdout to a file
        with open("jtr_output.txt", "w") as outfile:
            subprocess.run(
                ["john", f"--format={Hash_Format}",f"--max-run-time={run_time}", f"--wordlist={Wordlist}",File_of_Hash],
                stdout=outfile,
                stderr=subprocess.STDOUT,
                text=True
            )

        # Read the output file
        with open("jtr_output.txt", "r") as f:
            output = f.read()

            print(output)  # Debugging output, if necessary



            # Extract performance metrics (e.g., guesses per second, passwords per second)
            metrics_line = next((line for line in output.splitlines() if "g/s" in line), None)
            attack_type = f"{Hash_Format.upper()}-WL"
            if metrics_line:
                metrics = parse_metrics_line(metrics_line,attack_type)
                print("Wordlist Metrics:")
                print(metrics)



    except subprocess.TimeoutExpired:
        print("Wordlist attack timed out.")
    except subprocess.CalledProcessError:
        print("Error during wordlist attack.")

    total_end = time.time()
    total_time = total_end - total_start
    return total_time


def Run_JtR_Incremental(File_of_Hash, Hash_Format,run_time):
    print(f"\nStarting crack on {Hash_Format}")
    total_start = time.time()

    try:
        print("Running Incremental attack")
        # Redirect stdout to a file
        with open("jtr_output.txt", "w") as outfile:
            subprocess.run(
                ["john", f"--incremental",f"--max-run-time={run_time}", f"--format={Hash_Format}", File_of_Hash],

                stdout=outfile,
                stderr=subprocess.STDOUT,
                text=True
            )

        # Read the output file
        with open("jtr_output.txt", "r") as f:
            output = f.read()

            print(output)  # Debugging output, if necessary


            # Extract performance metrics (e.g., guesses per second, passwords per second)
            metrics_line = next((line for line in output.splitlines() if "g/s" in line), None)
            attack_type = f"{Hash_Format.upper()}-I"
            if metrics_line:
                metrics = parse_metrics_line(metrics_line,attack_type)
                print("Incremental Metrics:")
                print(metrics)


    except subprocess.TimeoutExpired:
        print("Incremental attack timed out.")
    except subprocess.CalledProcessError:
        print("Error during wordlist attack.")

    total_end = time.time()
    total_time = total_end - total_start
    return total_time
#Results Helper functions, pulls in data from JtR as well as timing from script to report back to User
def JtR_results(File_of_Hash,Format,Time,attack_label):

    result = subprocess.run(
        ["john", "--show", f"--format={Format}", File_of_Hash],
        capture_output=True,
        text=True
    )

    lines = result.stdout.strip().splitlines()
    cracked_passwords = []

    for line in lines:
        if not line or ':' not in line:
            continue
        parts = line.split(':', 1)
        if len(parts) == 2:
            password = parts[1].strip()
            cracked_passwords.append(password)

    cracked = bool(cracked_passwords)
    if cracked:
        print("\nCracked: True")
        print("Time to Crack: ", round(Time, 2), "Seconds")
        for pwd in cracked_passwords:
            print("Cracked Password:", pwd)
    else:
        print("\nCracked: False")

    # Store the result
    summary_results.append({
        "Hash": Format.upper(),
        "Attack": attack_label,
        "Cracked": cracked,
        "Password": ", ".join(cracked_passwords) if cracked_passwords else "-",
        "Time (s)": round(Time, 2),
        "g/s": performance_metrics[f"{Format.upper()}-{attack_label}"].get("g_s", 0),
        "p/s": performance_metrics[f"{Format.upper()}-{attack_label}"].get("p_s", 0),
        "c/s": performance_metrics[f"{Format.upper()}-{attack_label}"].get("c_s", 0)
    })


def clear_john_pot():

# Clears the john.pot file to reset previously cracked passwords.

    try:
        with open(JOHN_POT_PATH, "w") as f:
            f.truncate(0)  # Clears file contents
        print(" john.pot has been cleared.")
    except FileNotFoundError:
        print("'️ john.pot file not found—nothing to clear.")
    except Exception as e:
        print(f"Error clearing john.pot: {e}")



def parse_metrics_line(metrics_line,attack_type):
    match = re.search(r"(\d+\.?\d*[KMG]?)g/s\s+(\d+\.?\d*[KMG]?)p/s\s+(\d+\.?\d*[KMG]?)c/s", metrics_line,
                      re.IGNORECASE)
    if match:
        g_s, p_s, c_s = match.groups()
        store_metrics(attack_type, g_s, p_s, c_s)
        return (
            parse_speed(g_s),
            parse_speed(p_s),
            parse_speed(c_s)
        )
    return (0.0, 0.0, 0.0)

def parse_speed(value):
    multipliers = {'K': 1_000, 'M': 1_000_000, 'G': 1_000_000_000}
    if value[-1] in multipliers:
        try:
            return float(value[:-1]) * multipliers[value[-1]]
        except ValueError:
            return 0.0
    try:
        return float(value)
    except ValueError:
        return 0.0


def plot_metrics():
    hash_types = ["RAW-MD5", "RAW-SHA256", "BCRYPT"]
    attack_types = ["WL", "I"]
    attack_labels = ["Wordlist", "Incremental"]
    metrics = ["p_s", "c_s"]
    metric_labels = ["Passwords/sec", "Candidates/sec"]
    bar_width = 0.25

    for hash_type in hash_types:
        fig, ax = plt.subplots()
        index = np.arange(len(attack_types))  # Position for each attack type

        for i, metric in enumerate(metrics):
            # Collect data for this metric across both attacks
            values = [
                performance_metrics.get(f"{hash_type}-{atk}", {}).get(metric, 0)
                for atk in attack_types
            ]
            # Position each group slightly offset
            bar_positions = index + (i - 1) * bar_width
            ax.bar(bar_positions, values, width=bar_width, label=metric_labels[i])

        ax.set_xticks(index)
        ax.set_xticklabels(attack_labels)
        ax.set_title(f"Performance Metrics for {hash_type}")
        ax.set_ylabel("Rate")
        ax.legend()
        ax.grid(axis="y")
        plt.tight_layout()
        plt.show()

def plot_summary_table():
    column_labels = ["Hash", "Attack", "Cracked", "Password", "Time (s)", "g/s", "p/s", "c/s"]
    cell_data = []

    for entry in summary_results:
        row = [
            entry["Hash"],
            "Wordlist" if entry["Attack"] == "WL" else "Incremental",
            "Yes" if entry["Cracked"] else "No",
            entry["Password"],
            entry["Time (s)"],
            entry["g/s"],
            entry["p/s"],
            entry["c/s"]
        ]
        cell_data.append(row)

    fig, ax = plt.subplots(figsize=(12, 4))
    ax.axis('tight')
    ax.axis('off')
    table = ax.table(cellText=cell_data, colLabels=column_labels, loc='center', cellLoc='center')
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1.2, 1.2)
    plt.title("Password Cracking Summary", fontsize=14)
    plt.tight_layout()
    plt.show()


def run_all_attacks(hash_file, hash_format, wordlist, run_time):
    for attack_type in ["WL", "I"]:
        if attack_type == "WL":
            time_taken = Run_JtR_wordlist(hash_file, hash_format, wordlist, run_time)
        else:
            time_taken = Run_JtR_Incremental(hash_file, hash_format, run_time)
        JtR_results(hash_file, hash_format, time_taken, attack_type)
        clear_john_pot()

#Main Driving Function for the software
def main():
    user_input = input("Enter password string: ").strip()
    run_time = int(input("Enter time to attempt crack (in seconds): "))

    if not user_input:
        print("Password cannot be empty.")
        return
#Run Hashing helper function to hash into three different algorithms
    print("Hashing of Password will now commence!\n")
    MD5_Hash, SHA256_Hash, Bcrypt_Hash = hashing(user_input)

#Run File Write helper function to write the hashes to unique files
    print("\n The Hashes of the password will now be saved to a file!")
    md5_file, sha_file, bcrypt_file = File_Write(MD5_Hash,SHA256_Hash,Bcrypt_Hash)



    run_all_attacks(md5_file, "raw-md5", wordlist, run_time)
    run_all_attacks(sha_file, "raw-sha256", wordlist, run_time)
    run_all_attacks(bcrypt_file, "bcrypt", wordlist, run_time)


    for attack_type, metrics in performance_metrics.items():
        print(f"{attack_type}: {metrics['g_s']} g/s, {metrics['p_s']} p/s, {metrics['c_s']} c/s")

    plot_metrics()


    plot_summary_table()
if __name__ == "__main__":
    main()