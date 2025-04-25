#Necesary imports of other code modules
from core import hash_passwords, write_hashes, run_john_attacks,get_valid_password,get_valid_time
from metrics import performance_metrics, summary_results, initiate_metrics
from plotting import plot_metrics, plot_summary_table

#Driving Function for the software
def main():
    #Assignment of helper fuction values from core.py to variable for use
    user_password = get_valid_password()
    run_time = get_valid_time()

    #Running of helper fuction from metrics.py to initalize performance metrics dictionary.
    initiate_metrics()

    #Assignment of variables that match the hash performed on user input, printing of these variable, and creation of files utilizing the write_hashes helper
    #function
    md5, sha256, bcrypt = hash_passwords(user_password)
    print("MD5 Hash: ",md5, "\n", "SHA-256 Hash: ",sha256, "\n", "BCRYPT Hash: ",bcrypt)
    md5_file, sha_file, bcrypt_file = write_hashes(md5, sha256, bcrypt)

    #Utilization of the run_john_attacks function to, includes as parameters user run time and earlier created files.
    run_john_attacks(md5_file, "raw-md5", run_time)
    run_john_attacks(sha_file, "raw-sha256", run_time)
    run_john_attacks(bcrypt_file, "bcrypt", run_time)

    #Running of the plot_metrics and plot_summary_table functions to produce tables and graphs for user comprehension.
    plot_metrics()
    plot_summary_table()

    print("\nThank you for using the HCTool!")
if __name__ == "__main__":
    main()
