import socket
import time
import threading
import pickle
import csv
import os
from datetime import datetime
from scapy.all import sniff, IP, TCP
from sklearn.linear_model import SGDClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

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

# Function to log packet details into the CSV file
def log_packet_to_csv(src_ip, dest_ip, protocol, packet_length, status):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = [src_ip, dest_ip, protocol, packet_length, status, timestamp]

    with open(csv_file_name, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(log_entry)
    print(f"Logged packet: {log_entry}")

# Initial rules
MAX_PACKET_SIZE = 1400
IDS_PORT = 11234  # Port to listen for connections

# Initialize the classifier and scaler
clf = SGDClassifier(loss='hinge', random_state=42)
scaler = StandardScaler()

# Placeholder for training data
training_data = []  # List to collect features of dropped packets
labels = []  # Labels for dropped packets (1 for suspicious, 0 for normal)

# Queue to hold packets when traffic is isolated
packet_queue = []
processed_packets = set()  # To avoid repeated prompts for the same packet

# Socket to listen for traffic
def create_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", IDS_PORT))  # Listening on all IPs and port 11234
    s.listen(5)  # Max 5 connections
    print(f"Socket listening on port {IDS_PORT}...")
    return s

# Function to extract features from packets
def extract_features(packet):
    features = []
    if packet.haslayer(TCP):
        features.append(len(packet))  # Packet length
        features.append(packet[TCP].sport)  # Source port
        features.append(packet[TCP].dport)  # Destination port
        features.append(packet[IP].src)  # Source IP
        features.append(packet[IP].dst)  # Destination IP
    return features

# Rule-based packet inspection (suspicion)
def is_suspicious(packet):
    # Check packet size
    if len(packet) > MAX_PACKET_SIZE:
        return True
    return False

# Function to handle packet sniffing and learning
def packet_sniffer():
    global MAX_PACKET_SIZE, processed_packets  # Access global variables

    def process_packet(packet):
        global MAX_PACKET_SIZE  # Ensure MAX_PACKET_SIZE is updated globally
        if packet.haslayer(IP):
            packet_len = len(packet)
            src_ip = packet[IP].src
            dest_ip = packet[IP].dst
            protocol = packet[IP].proto  # Protocol number
            packet_summary = f"{packet.summary()} (Length: {packet_len})"

            # Allow normal packets below the threshold
            if not is_suspicious(packet):
                print(f"[NORMAL] {packet_summary} (Allowed)")
                log_packet_to_csv(src_ip, dest_ip, protocol, packet_len, "Allowed")
                training_data.append(extract_features(packet))
                labels.append(0)  # Mark as normal
                return

            # Handle suspicious packets
            if packet_summary not in processed_packets:
                print(f"\n[ALERT] Suspicious packet detected: {packet_summary}")
                user_input = input("Drop the packet (y/n)? ").strip().lower()

                if user_input == 'y':
                    print("Packet dropped.")
                    log_packet_to_csv(src_ip, dest_ip, protocol, packet_len, "Dropped")
                    # Dynamically adjust the threshold
                    new_threshold = (MAX_PACKET_SIZE + packet_len) // 2
                    print(f"Adjusting MAX_PACKET_SIZE from {MAX_PACKET_SIZE} to {new_threshold}.")
                    MAX_PACKET_SIZE = new_threshold
                    training_data.append(extract_features(packet))
                    labels.append(1)  # Mark as suspicious
                elif user_input == 'n':
                    print("Packet allowed.")
                    log_packet_to_csv(src_ip, dest_ip, protocol, packet_len, "Allowed")
                    training_data.append(extract_features(packet))
                    labels.append(0)  # Mark as normal

                # Track processed packets to avoid repeated prompts
                processed_packets.add(packet_summary)

    # Start sniffing on the network interface
    sniff(iface="enp0s8", filter="ip", prn=process_packet, store=0)

# Function to train the model periodically
def train_model():
    global clf, scaler
    # Check if there is enough data to train the model
    if len(training_data) > 50:  # Use a threshold for training (e.g., 50 packets)
        print("Training the model...")

        # Convert the training data to numpy arrays
        X = scaler.fit_transform(training_data)  # Scale the features
        y = labels

        # Split data into train/test sets
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

        # Train the model
        clf.fit(X_train, y_train)

        # Save the model
        with open('trained_model.pkl', 'wb') as f:
            pickle.dump(clf, f)
        print("Model trained and saved.")

        # Clear training data to start fresh
        training_data.clear()
        labels.clear()

# Function to load the pre-trained model if available
def load_model():
    global clf
    try:
        with open('trained_model.pkl', 'rb') as f:
            clf = pickle.load(f)
        print("Model loaded successfully!")
    except:
        print("No pre-trained model found. Starting fresh.")

# Function to handle socket connections (Listen and process traffic)
def socket_listener():
    s = create_socket()
    while True:
        # Accept new connections
        conn, addr = s.accept()
        print(f"Connection from {addr} established.")
        try:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                print(f"Received data: {data}")

        except Exception as e:
            print(f"Error: {e}")
            conn.close()

# Main loop
def main():
    load_model()  # Load the pre-trained model if available

    # Start sniffing packets
    sniff_thread = threading.Thread(target=packet_sniffer)
    sniff_thread.start()

    # Start the socket listener
    socket_thread = threading.Thread(target=socket_listener)
    socket_thread.start()

    while True:
        # Periodically train the model with the captured data
        if len(training_data) > 50:  # Train when enough packets have been captured
            train_model()
        time.sleep(5)  # Delay before the next iteration of sniffing and socket handling

if __name__ == "__main__":
    main()
