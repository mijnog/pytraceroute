import argparse
from scapy.all import *

def traceroute(destination, max_hops=30, timeout=2):
    print(f"Traceroute to {destination} with a maximum of {max_hops} hops:")
    
    for ttl in range(1, max_hops + 1):
        # Create an ICMP packet with the current TTL
        packet = IP(dst=destination, ttl=ttl) / ICMP()
        response = sr1(packet, verbose=0, timeout=timeout)
        
        if response is None:
            print(f"{ttl}: Request timed out.")
        elif response.type == 0:  # Echo reply
            print(f"{ttl}: {response.src} (Reached the destination)")
            break
        else:  # Time exceeded
            print(f"{ttl}: {response.src} (TTL exceeded)")

if __name__ == "__main__":
    # Set up argument parsing
    parser = argparse.ArgumentParser(description='Perform a traceroute to a specified destination IP or hostname.')
    parser.add_argument('destination', type=str, help='The IP address or hostname to trace.')
    args = parser.parse_args()

    # Call the traceroute function with the provided destination
    traceroute(args.destination)

