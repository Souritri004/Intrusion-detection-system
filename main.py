import threading
import pyshark
import pandas as pd
import time
from queue import Queue
import warnings
import asyncio

# Suppress warnings related to unclosed transport (optional)
warnings.filterwarnings("ignore", category=ResourceWarning)

# Function to capture traffic from the specified network interface
def capture_traffic(data_queue, interface="Wi-Fi"):
    def sniff():
        # Create and set an event loop for the current thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            # Start live capture from the specified interface
            capture = pyshark.LiveCapture(interface=interface)
            for packet in capture.sniff_continuously():  # Synchronous generator
                data_queue.put(packet)  # Add packet to the queue
        except Exception as e:
            print(f"Error in sniffing: {e}")
        finally:
            # Ensure to close the capture gracefully
            capture.close()
            loop.close()

    # Run sniff in a separate thread with event loop handling
    try:
        threading.Thread(target=sniff).start()  # Start sniffing in a new thread
    except Exception as e:
        print(f"Error in creating sniff thread: {e}")

# Function to detect anomalies (or process the captured data)
def anomaly_detection_thread(data_queue):
    while True:
        packet = data_queue.get()
        if packet is None:  # Stop the loop if None is put in the queue
            break
        
        # Extract useful packet information (e.g., packet size, source IP, protocol)
        packet_size = len(packet)  # Size of the packet in bytes
        packet_info = {
            'Packet Info': str(packet),
            'Size': packet_size
        }
        
        # Example of anomaly detection: check for unusually large packets
        if packet_size > 1500:  # For example, flag packets larger than 1500 bytes
            print(f"Anomaly detected: Large packet of size {packet_size} bytes!")
            #print(packet_info)

        # Example of anomaly detection: check for unknown source or destination IP
        if "IP" in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            if not src_ip.startswith("192.168"):  # Example: IPs not in the 192.168 range
                print(f"Anomaly detected: Unexpected source IP {src_ip}!")
            if not dst_ip.startswith("192.168"):  # Example: IPs not in the 192.168 range
                print(f"Anomaly detected: Unexpected destination IP {dst_ip}!")

        # You can add more detection logic based on your requirements (e.g., protocol, ports, etc.)
        #print(f"Processing packet: {packet}")

# Function to save captured data to a CSV file
def save_to_csv(dataframe: pd.DataFrame, filename="traffic_data1.csv"):
    try:
        dataframe.to_csv(filename, index=False)
        print(f"Data saved to {filename}")
    except Exception as e:
        print(f"Error saving data to CSV: {e}")

# Main function to start the capture and detection threads
if __name__ == "__main__":
    data_queue = Queue()

    # Start the traffic capture thread with the updated interface
    capture_thread = threading.Thread(target=capture_traffic, args=(data_queue, "Wi-Fi"))
    capture_thread.start()

    # Start the anomaly detection thread
    detection_thread = threading.Thread(target=anomaly_detection_thread, args=(data_queue,))
    detection_thread.start()

    try:
        while True:
            # Keep the main thread running to allow continuous sniffing
            if not data_queue.empty():
                packet = data_queue.get()  # Get packet from the queue
                # Additional processing can be done here if necessary
    except KeyboardInterrupt:
        print("Exiting program.")
    
    # Gracefully stop the capture and join the threads
    data_queue.put(None)  # Add stop signal to the queue for detection thread
    capture_thread.join()  # Wait for the capture thread to finish
    detection_thread.join()  # Wait for the detection thread to finish