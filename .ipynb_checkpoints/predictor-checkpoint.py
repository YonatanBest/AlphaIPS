import pandas as pd
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import joblib

# Load the trained model
model = joblib.load('trained_model.pkl')

# Function to map ports to services
def get_service(port):
    service_mapping = {
        80: "http",
        443: "https",
        21: "ftp",
        20: "ftp-data",
        22: "ssh",
        53: "dns",
        25: "smtp",
        110: "pop3",
        143: "imap",
        3389: "rdp",
        23: "telnet"
        # Add more services and ports as needed
    }
    return service_mapping.get(port, "other")

# Define a dictionary to hold flow data
flows = defaultdict(lambda: {
    "start_time": None,
    "src_bytes": 0,
    "dst_bytes": 0,
    "count": 0,
    "srv_count": 0,
    "protocol_type": None,
    "service": None,
    "flag": None,
    "land": None
})

# Initialize the DataFrame to store the results
columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", 
    "count", "srv_count", "result"
]

df = pd.DataFrame(columns=columns)

# To handle symbolic fields
protocol_mapping = {6: "tcp", 17: "udp", 1: "icmp"}

# Function to extract features from a packet
def extract_features(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Use (src_ip, dst_ip, src_port, dst_port) as flow identifier
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = 6  # TCP
            flag = packet[TCP].flags
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = 17  # UDP
            flag = None
        elif ICMP in packet:
            src_port = None
            dst_port = None
            protocol = 1  # ICMP
            flag = None
        else:
            return  # Not TCP, UDP, or ICMP, we skip this packet

        # Unique flow identifier
        flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)

        # Check if this flow is new
        if flows[flow_key]["start_time"] is None:
            flows[flow_key]["start_time"] = time.time()
            flows[flow_key]["protocol_type"] = protocol_mapping.get(protocol, "other")
            flows[flow_key]["service"] = get_service(dst_port)
            flows[flow_key]["flag"] = flag

        # Update flow data
        flows[flow_key]["count"] += 1
        flows[flow_key]["src_bytes"] += len(packet[IP])
        flows[flow_key]["dst_bytes"] += len(packet[IP]) if packet[IP].src != src_ip else 0
        flows[flow_key]["land"] = 1 if packet[IP].src == src_ip else 0
        flows[flow_key]["srv_count"] += 1 if flows[flow_key]["service"] else 0
        
        # Duration of the flow
        duration = time.time() - flows[flow_key]["start_time"]

        # Prepare a row of data
        df_row = {
            "duration": duration,
            "protocol_type": flows[flow_key]["protocol_type"],
            "service": flows[flow_key]["service"],
            "flag": flows[flow_key]["flag"],
            "src_bytes": flows[flow_key]["src_bytes"],
            "dst_bytes": flows[flow_key]["dst_bytes"],
            "land": flows[flow_key]["land"],
            "count": flows[flow_key]["count"],
            "srv_count": flows[flow_key]["srv_count"]
        }

        # Append row to the DataFrame
        df.loc[len(df)] = df_row

        # Prepare the data for prediction
        X_new = pd.DataFrame([df_row])

        # One-hot encode the categorical variables
        X_new = pd.get_dummies(X_new, columns=['protocol_type', 'service', 'flag'])

        # Reindex to match the training data, ignoring new features
        X_new = X_new.reindex(columns=model.feature_names_in_, fill_value=0)

        # Make prediction
        y_pred = model.predict(X_new)

        # Map prediction to labels
        df_row['result'] = 'abnormal' if y_pred[0] == 1 else 'normal'

        # Update the existing row with the prediction
        df.loc[len(df) - 1, 'result'] = df_row['result']

        # Save to CSV after every packet (or batch this to improve performance)
        df.to_csv("network_traffic_predicted.csv", index=False)

# Start sniffing
while True:
    sniff(prn=extract_features)  # Adjust count or filter as needed
