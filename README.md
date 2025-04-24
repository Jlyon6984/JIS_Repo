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

---

## Project Structure
password_cracker/
├── main.py                   # Main script to run the tool
├── plotting.py               # Handles creation of graphs and table
├── core.py                   # Runs JtR, performs hashing, 
├── metrics.py                # Parses and normalizesperformance metrics from JtR output
├── wordlist.txt              # Wordlist used for dictionary attacks
├── README.md                 # You're here!


