# Password Hashing & Cracking Performance Analyzing Tool

A Python-based tool that hashes a user-provided password using **MD5**, **SHA-256**, and **bcrypt**, then attempts to crack each hash using [John the Ripper](https://www.openwall.com/john/). The tool performs both **wordlist** and **incremental** attacks, tracks performance metrics, and visualizes the results with informative bar graphs and summary tables.

---

## Features

- Hashes passwords with **MD5**, **SHA-256**, and **bcrypt**
- Cracks hashes using **John the Ripper** in:
  - Wordlist mode
  - Incremental mode
- Collects and parses cracking metrics:
  - Guesses per second (g/s)
  - Passwords per second (p/s)
  - Candidates per second (c/s)
- Tracks cracking time and success
- Visualizes results using `matplotlib`:
  - Bar charts for performance
  - Summary table of attempts
  - allows for user input of password
  - allows for user set timeouts

---

## Project Structure
password_cracker/
├── HCTool.py 
├── plotting.py           
├── core.py                   
├── metrics.py               
├── wordlist.txt             
├── README.md               

---
## Requirements 
- Python 3.8+
- [John the Ripper](https://www.openwall.com/john/)
- Python Packages:
- hashlib
- bcrypt
- subprocess
- time
- numpy
- matplotlib
- re
---
## Usage
Run tool by executing:
python HCTool.py

When prompted, enter in the password to test and the maximum cracking time, in seconds you would like to use.

The tool will then:
-Generate and write the hashes to seperate files.
- Run JtR in both wordlist and incremental modes for each hash type.
- Capture performance metrics and cracking status
- Display visual charts and a summary table of the results.



