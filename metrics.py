#Importation of subprocess and regular expression libraries for use
import subprocess
import re

#Declaration of a global dictionary and global array for use in metrics storage and manipulation.
performance_metrics = {}
summary_results = []

#Helper function to initiate values in performance metrics array for later use.
def initiate_metrics():
    for hash in ["RAW-MD5", "RAW-SHA256", "BCRYPT"]:
        for mode in ["WL", "I"]:
            performance_metrics[f"{hash}-{mode}"] = {"g_s": 0, "p_s": 0, "c_s": 0}

#Function to help normalize the metrics reported by JtR for easier comprehension in tables and graphs.
def normalize_speed(val):
    scale = {'K': 1_000, 'M': 1_000_000, 'G': 1_000_000_000}
    return float(val[:-1]) * scale.get(val[-1], 1) if val[-1] in scale else float(val)

#Uses developed regular expression to parse valuable metrics from JtR command line when available
#Runs the parsed values through the normalize_speed function to normalize results.
def parse_metrics_line(line, key):
    #use of regular expression to create different match groups.
    match = re.search(r"(\d+\.?\d*[KMG]?)g/s\s+(\d+\.?\d*[KMG]?)p/s\s+(\d+\.?\d*[KMG]?)c/s", line)

    #If these groups exist they are assigned to three different variables and then normalized.
    if match:
        guesses, passwords, candidates = match.groups()
        performance_metrics[key] = {
            "g/s": normalize_speed(guesses),
            "p/s": normalize_speed(passwords),
            "c/s": normalize_speed(candidates),
        }

#Function that saves the result of the john -show command to
def record_result(file, fmt, label,time):
    #This code chunk saves the output of john -show to a variable "result"
    result = subprocess.run(["john", "--show", f"--format={fmt}", file],
                            capture_output=True, text=True)

    #This chunk parses for the password if cracked in JtR
    cracked = [l.split(":", 1)[1].strip() for l in result.stdout.splitlines() if ":" in l]
    cracked_password = ", ".join(cracked) if cracked else "-"

    #This chunk appends to the summary results dictionary different values for each attack run.
    summary_results.append({
        "Hash": fmt.upper(),
        "Attack": label,
        "Cracked": bool(cracked),
        "Password": cracked_password,
        "Time (s)": round(time, 2),
        **performance_metrics.get(f"{fmt.upper()}-{label}", {})
    })
