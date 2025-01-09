import csv
import os
import time
import threading
import signal
import sys
from scapy.all import sniff, IP, TCP, UDP
from sklearn.linear_model import SGDClassifier
from datetime import datetime
from queue import Queue
import socket
from sklearn.datasets import make_classification

# File and headers for CSV logging
csv_file_name = "traffic_logs.csv"
csv_headers = ["Source IP", "Destination IP", "Protocol", "Packet Length", "Status", "Timestamp"]

# Ensure the CSV exists with headers
if not os.path.exists(csv_file_name):
    with open(csv_file_name, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(csv_headers)

# Shared queue for logs and alerts
log_queue = Queue()
alert_queue = Queue()

# Graceful shutdown signal
shutdown_event = threading.Event()

# Signal handling for graceful shutdown
def handle_shutdown(signal_number, frame):
    print("\nShutting down IDS...")
    shutdown_event.set()

signal.signal(signal.SIGINT, handle_shutdown)
signal.signal(signal.SIGTERM, handle_shutdown)

# Sample feature generation for packet (using length, protocol, and source IP as features)
def generate_features(packet):
    try:
        packet_length = len(packet)
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        source_ip = packet[IP].src
        
        # Convert protocol to a numerical feature (e.g., TCP = 1, UDP = 2, Other = 0)
        protocol_feature = 1 if protocol == "TCP" else 2 if protocol == "UDP" else 0

        # Convert source IP to an integer (e.g., simple hashing of the IP address)
        source_ip_feature = int.from_bytes(socket.inet_aton(source_ip), 'big')

        # Return a list of 3 features (packet length, protocol as int, and source IP as int)
        return [packet_length, protocol_feature, source_ip_feature]
    except Exception as e:
        print(f"[Error] Feature generation failed: {e}")
        return [0, 0, 0]  # Default return value if error occurs

# Function to log traffic to the CSV
def log_traffic(source_ip, dest_ip, protocol, length, status):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = [source_ip, dest_ip, protocol, length, status, timestamp]
    log_queue.put(log_entry)

# Packet sniffer thread
def packet_sniffer(model):
    print("[Thread: Packet Sniffer] Started.")
    
    def process_packet(packet):
        try:
            # Generate features from the packet
            features = generate_features(packet)
            # Predict the status (Normal or Suspicious) based on features
            prediction = model.predict([features])
            status = "Suspicious" if prediction == 1 else "Normal"

            source_ip = packet[IP].src
            dest_ip = packet[IP].dst
            protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
            packet_length = len(packet)

            # Log the traffic
            log_traffic(source_ip, dest_ip, protocol, packet_length, status)

            # If suspicious, trigger an alert
            if status == "Suspicious":
                alert_queue.put(f"ALERT: Suspicious packet from {source_ip} -> {dest_ip}, Length: {packet_length}")
        
        except Exception as e:
            print(f"[Error] Packet processing error: {e}")

    # Start sniffing packets
    sniff(filter="ip", prn=process_packet, store=False, stop_filter=lambda _: shutdown_event.is_set())

# Alerts thread
def alerts_display():
    print("[Thread: Alerts Display] Started.")
    while not shutdown_event.is_set():
        while not alert_queue.empty():
            alert = alert_queue.get()
            print(f"[ALERT] {alert}")
        time.sleep(0.5)

# Logs thread
def logs_writer():
    print("[Thread: Logs Writer] Started.")
    while not shutdown_event.is_set():
        while not log_queue.empty():
            log_entry = log_queue.get()
            with open(csv_file_name, mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(log_entry)
        time.sleep(1)

# Clear logs function (can be called manually or from a separate script)
def clear_logs():
    with open(csv_file_name, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(csv_headers)
    print("[LOGS] Logs have been cleared.")

# Load or train the model
def load_or_train_model():
    try:
        print("[INFO] Training a new model...")

        # Corrected dataset generation with 3 features
        X, y = make_classification(n_samples=1000, n_features=3, n_informative=2, n_redundant=0, n_classes=2, random_state=42)

        # Initialize SGDClassifier
        model = SGDClassifier()

        # Train the model
        model.fit(X, y)
        print("[INFO] Model trained successfully.")
        return model
    except Exception as e:
        print(f"[Error] Model training failed: {e}")
        sys.exit(1)

# Main function to start threads
def main():
    # Load or train the model
    model = load_or_train_model()

    # Start threads for sniffer, alerts, and logging
    threads = [
        threading.Thread(target=packet_sniffer, args=(model,)),
        threading.Thread(target=alerts_display),
        threading.Thread(target=logs_writer),
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    print("Starting IDS... Press Ctrl+C to stop.")
    main()
