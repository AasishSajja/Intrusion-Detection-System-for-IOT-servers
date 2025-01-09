import socket
import time
import threading
import pickle
from scapy.all import sniff, IP, TCP
from sklearn.linear_model import SGDClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

# Initial rules
MAX_PACKET_SIZE = 1400
IDS_PORT = 11234  # Port to listen for connections

# Initialize the classifier and scaler
clf = SGDClassifier(loss='hinge', random_state=42)
scaler = StandardScaler()

# Placeholder for training data
training_data = []  # List to collect features of packets
labels = []  # Labels for packets (1 for suspicious, 0 for normal)

# Set to track processed packets (to avoid re-prompting for the same packet)
processed_packets = set()


# Function to extract features from packets
def extract_features(packet):
    features = []
    if packet.haslayer(TCP):
        features.append(len(packet))  # Packet length
        features.append(packet[TCP].sport)  # Source port
        features.append(packet[TCP].dport)  # Destination port
    return features


# Rule-based packet inspection (suspicion)
def is_suspicious(packet):
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
            packet_summary = f"{packet.summary()} (Length: {packet_len})"

            # Allow normal packets below the threshold
            if not is_suspicious(packet):
                print(f"[NORMAL] {packet_summary} (Allowed)")
                training_data.append(extract_features(packet))
                labels.append(0)  # Mark as normal
                return

            # Handle suspicious packets
            if packet_summary not in processed_packets:
                print(f"\n[ALERT] Suspicious packet detected: {packet_summary}")
                user_input = input("Drop the packet (y/n)? ").strip().lower()

                if user_input == 'y':
                    print("Packet dropped.")
                    # Dynamically adjust the threshold
                    new_threshold = (MAX_PACKET_SIZE + packet_len) // 2
                    print(f"Adjusting MAX_PACKET_SIZE from {MAX_PACKET_SIZE} to {new_threshold}.")
                    MAX_PACKET_SIZE = new_threshold
                    training_data.append(extract_features(packet))
                    labels.append(1)  # Mark as suspicious
                elif user_input == 'n':
                    print("Packet allowed.")
                    training_data.append(extract_features(packet))
                    labels.append(0)  # Mark as normal

                # Track processed packets to avoid repeated prompts
                processed_packets.add(packet_summary)

    # Start sniffing on the network interface
    sniff(iface="enp0s8", filter="ip", prn=process_packet, store=0)


# Function to train the model periodically
def train_model():
    global clf, scaler
    if len(training_data) > 50:  # Train the model when sufficient data is available
        print("Training the model...")
        X = scaler.fit_transform(training_data)
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
    except FileNotFoundError:
        print("No pre-trained model found. Starting fresh.")


# Main loop
def main():
    load_model()

    # Start sniffing packets
    sniff_thread = threading.Thread(target=packet_sniffer)
    sniff_thread.daemon = True
    sniff_thread.start()

    while True:
        if len(training_data) > 50:
            train_model()
        time.sleep(5)  # Delay before rechecking


if __name__ == "__main__":
    main()
