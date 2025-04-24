

#Importation of necesary library as well as helper fuction from metrics.py
import numpy as np
from metrics import performance_metrics
import matplotlib.pyplot as plt
from metrics import summary_results

#Larger function to plot different metrics produced by JtR to bar graphs
def plot_metrics():
    #Creation of arrays containing different needed labels, as well as a set bar width variable
    hash_types = ["RAW-MD5", "RAW-SHA256", "BCRYPT"]
    attack_types = [("WL", "Wordlist"), ("I", "Incremental")]
    metrics = [ "p/s", "c/s"]
    metric_labels = [ "Passwords/sec", "Candidates/sec"]
    bar_width = 0.35


# This nested for loop iterates through each hash and attack type and saves the combination in a key variable.
# It then uses that key to acquire all metrics from the performance_metrics dictionary and plots them in a bar chart.
    for hash_type in hash_types:
        for atk_suffix, atk_label in attack_types:
            key = f"{hash_type}-{atk_suffix}"  # Build dictionary key like "MD5-wordlist"

            # Extract values for each metric (g/s, p/s, c/s) for the given hash-attack combo.
            # If a metric is missing, default to 0.
            values = [
                performance_metrics.get(key, {}).get(metric, 0)
                for metric in metrics]

            # Create a bar chart for the current hash and attack type
            fig, ax = plt.subplots()
            index = np.arange(len(metrics))  # X-axis positions for bars
            bars = ax.bar(index, values, width=bar_width, color=["#4CAF50", "#2196F3", "#FFC107"])

            # Label values on top of each bar
            for bar in bars:
                yval = bar.get_height()
                ax.text(
                    bar.get_x() + bar.get_width() / 2.0,
                    yval + 0.05 * max(values),
                    f"{yval:.1f}",
                    ha='center',
                    fontsize=8
                )

            # Set labels and titles
            ax.set_xticks(index)
            ax.set_xticklabels(metric_labels)
            ax.set_title(f"{atk_label} Attack - {hash_type}")
            ax.set_ylabel("Rate")
            ax.set_ylim(0, max(values) * 1.2 if max(values) > 0 else 1)  # Scale y-axis
            ax.grid(axis="y", linestyle="--", alpha=0.6)

            # Adjust layout and display the plot
            plt.tight_layout()
            plt.show()

    # This function Displays a summary table of all cracking attempts.
    # The table includes hash type, attack type, cracked status, cracked password,
    # cracking time, and performance metrics (g/s, p/s, c/s).
def plot_summary_table():


    column_labels = ["Hash", "Attack", "Cracked", "Password", "Time (s)", "g/s", "p/s", "c/s"]
    cell_data = []

    # Build table rows from summary_results list
    for entry in summary_results:
        row = [
            entry["Hash"],
            "Wordlist" if entry["Attack"] == "WL" else "Incremental",  # Convert short form to readable label
            "Yes" if entry["Cracked"] else "No",
            entry["Password"],
            round(entry["Time (s)"], 2),
            entry["g/s"],
            entry["p/s"],
            entry["c/s"]
        ]
        cell_data.append(row)

    # Create and format the summary table
    fig, ax = plt.subplots(figsize=(12, 4 + len(cell_data) * 0.3))  # Dynamically size figure height by row count
    ax.axis('tight')
    ax.axis('off')

    table = ax.table(
        cellText=cell_data,
        colLabels=column_labels,
        loc='center',
        cellLoc='center'
    )

    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1.2, 1.2)

    # Add title and layout adjustments
    plt.title("Password Cracking Summary", fontsize=14)
    plt.tight_layout()
    plt.show()
