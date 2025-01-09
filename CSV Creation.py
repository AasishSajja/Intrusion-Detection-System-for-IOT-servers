import csv
import os

# Define the CSV file name
csv_file_name = "traffic_logs.csv"

# Define the headers for the CSV
csv_headers = ["Source IP", "Destination IP", "Protocol", "Packet Length", "Status", "Timestamp"]

# Check if the CSV file already exists
if not os.path.exists(csv_file_name):
    # Create the file and write the headers
    with open(csv_file_name, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(csv_headers)
    print(f"{csv_file_name} created successfully with headers: {', '.join(csv_headers)}")
else:
    print(f"{csv_file_name} already exists. No changes were made.")
