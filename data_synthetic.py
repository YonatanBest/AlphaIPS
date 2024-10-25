import csv
import random

# Set number of samples
num_samples = 10000000

protocol_types = [
    "tcp", "udp", "icmp", "igmp", "sctp", "ospf", "arp", "rarp", "gre",
    "esp", "ah", "eigrp", "pim", "vrrp", "mpls", "ip", "icmpv6", "igmpv3",
    "rsvp", "bgp", "dccp"
]

services = [
    "http", "https", "ftp", "sftp", "smtp", "pop3", "imap", "dns", "dhcp",
    "ssh", "telnet", "ldap", "tftp", "snmp", "ntp", "icmp", "bgp", "rdp",
    "sip", "h323", "rtsp", "sqlnet", "redis", "mongodb", "cassandra", "kafka",
    "zookeeper", "kerberos", "radius", "vxlan", "gopher", "whois", "finger",
    "irc", "nntp", "nis", "nbns", "smb", "cifs", "rdp", "nfs", "ncp", "mqtt",
    "stun", "ldap", "mdns", "netbios", "x11", "imap", "irc", "bitcoin",
    "ipsec", "l2tp", "pptp", "sip", "icmp", "icmpv6", "mdns", "mpls", "ospf"
]

flags = [
    "SF", "REJ", "S0", "RSTO", "RSTR", "RSTOS0", "SH", "SHR", "OTH",
    "SYN", "ACK", "FIN", "PSH", "URG", "ECE", "CWR"
]

def generate_sample(label="normal"):
    duration = round(random.uniform(0.0, 20.0 if label == "normal" else 1000.0), 1)
    protocol_type = random.choice(protocol_types)
    service = random.choice(services)
    flag = random.choice(flags)
    src_bytes = random.randint(0, 5000 if label == "normal" else 10000)
    dst_bytes = random.randint(0, src_bytes if label == "normal" else 5000)
    land = random.randint(0, 1) if label == "abnormal" else 0
    count = random.randint(1, 20 if label == "normal" else 100)
    srv_count = random.randint(1, 10 if label == "normal" else 50)
    result = label
    return [duration, protocol_type, service, flag, src_bytes, dst_bytes, land, count, srv_count, result]

with open("realistic_network_data.csv", mode="w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "count", "srv_count", "result"])
    
    for _ in range(num_samples):
        label = "normal" if random.random() < 0.8 else "abnormal"
        writer.writerow(generate_sample(label))
print("Done!")
