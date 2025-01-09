Intrusion Detection System (IDS) for IoT Devices on the Network Side
Overview
This project focuses on developing a lightweight Intrusion Detection System (IDS) designed for IoT networks. The system combines rule-based thresholds with machine learning techniques to detect and isolate malicious traffic. It is tailored for resource-constrained environments, ensuring real-time anomaly detection, logging, and traffic management.

The IDS supports self-learning from live data in the absence of pre-trained models and integrates modular logging for traceability. The system also includes mechanisms to fall back on rule-based detection for seamless operation in diverse IoT scenarios.

Features
Hybrid Detection: Combines rule-based thresholds with machine learning models for advanced anomaly detection.
Self-Learning Mechanism: Collects live data and updates detection capabilities dynamically.
Protocol Support: Includes a protocol map for handling multiple IoT communication protocols.
Traffic Isolation: Suspicious traffic is quarantined to prevent network disruptions.
Comprehensive Logging: Logs all traffic details, anomalies, and actions taken.
Real-Time Performance: Designed for low-latency, high-throughput IoT environments.

Installation and Setup

1. Prerequisites
System Requirements:
Python 3.7+
Minimum 4 GB RAM
Oracle VirtualBox (for virtualized environments)

Tools and Libraries:
scapy
numpy
pandas
sklearn
matplotlib (for visualizations)
Install the required Python libraries:
pip install scapy numpy pandas scikit-learn matplotlib

2. Clone the Repository

git clone https://github.com/your_username/ids-for-iot.git
cd ids-for-iot

3. Configure the Environment
Dataset:
Download the CICIDS2017 dataset or provide live traffic data from your IoT network.
Place the dataset in the /data folder.

Network Configuration:
Update the config.py file with network details such as:

Subnet ranges
Protocols to monitor
Threshold values for rule-based detection

4. Running the IDS
Start the Packet Capture:
python packet_sniffer.py
This will capture live network traffic and save it for further analysis.

Run the Detection Engine:

python detection_engine.py
This will process traffic in real-time, detect anomalies, and log results.

Manual Review Interface:
For reviewing quarantined traffic, use:

python review_interface.py

5. Simulating Attacks (Optional)
Use a Kali Linux VM to simulate network attacks, such as:

DoS/DDoS: Using tools like hping3.
MITM: Using ettercap.
Packet Injection: Using scapy.
Example for generating a DDoS attack:

hping3 -S -p 80 --flood <target_IP>

6. Viewing Logs
All logs are saved in the logs/ directory. You can analyze them using any text editor or import them into tools like Excel for detailed review.

Contributing
Contributions are welcome!

Fork the repository.
Create a new branch for your feature/bug fix.
Submit a pull request with detailed explanations.
License
This project is licensed under the MIT License. See the LICENSE file for details.

Acknowledgments
Datasets: CICIDS2017
Tools: Scapy, Python, and Kali Linux
Inspiration: Addressing real-world IoT security challenges
