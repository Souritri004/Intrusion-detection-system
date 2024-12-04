import threading
import pyshark
import pandas as pd
import time
from queue import Queue
import warnings
import asyncio
import threading
import pyshark
from queue import Queue

# Function to capture traffic
def capture_traffic(data_queue, interface="Wi-Fi"):
    # Create and set an event loop for the current thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    def sniff():
        try:
            capture = pyshark.LiveCapture(interface=interface)
            for packet in capture.sniff_continuously():  # Synchronous generator
                data_queue.put(packet)  # Add packet to the queue
        except Exception as e:
            print(f"Error in sniffing: {e}")
    
    # Run sniff in the event loop
    try:
        loop.run_in_executor(None, sniff)
        loop.run_forever()
    except Exception as e:
        print(f"Error in loop: {e}")
    finally:
        loop.close()

# Function to detect anomalies (or process the captured data)
def anomaly_detection_thread(data_queue, detector=None):
    while True:
        packet = data_queue.get()
        if packet is None:  # Stop the loop if None is put in the queue
            break
        
        # Process your packet here (e.g., extracting useful info)
        print(f"Processing packet: {packet}")
        # If you have detection logic, implement it here

# Function to save captured data to a CSV file
def save_to_csv(dataframe: pd.DataFrame, filename="traffic_data1.csv"):
    try:
        dataframe.to_csv(filename, index=False)
        print(f"Data saved to {filename}")
    except Exception as e:
        print(f"Error saving data to CSV: {e}")

# Main function to start the capture and detection threads
def main():
    data_queue = Queue()

    # Start the traffic capture thread
    capture_thread = threading.Thread(target=capture_traffic, args=(data_queue, "Wi-Fi"))
    capture_thread.start()

    # Start the anomaly detection thread
    detection_thread = threading.Thread(target=anomaly_detection_thread, args=(data_queue, None))
    detection_thread.start()

    # Wait for the threads to complete (this is a basic example; you may want to join with timeouts or conditions)
    capture_thread.join()
    detection_thread.join()

    # After threads finish, ensure the queue is processed and data is saved
    # Create a sample DataFrame to save (replace with your actual processed data)
    sample_data = {
        "Packet Info": ["Example data 1", "Example data 2"],  # Replace with actual packet data
        "Timestamp": [time.time(), time.time()]  # Example timestamp
    }

    df = pd.DataFrame(sample_data)
    save_to_csv(df, "traffic_data1.csv")

if __name__ == "__main__":import pyshark
import threading
import queue
import pandas as pd
import asyncio

# Function to capture live traffic in a separate thread
def capture_traffic1(interface="Wi-Fi", duration=10, data_queue=None):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    capture = pyshark.LiveCapture(interface=interface)
    packets = []

    # Capture for a set duration
    for packet in capture.sniff_continuously(packet_count=duration):
        try:
            packet_data = {
                'time': packet.sniff_time,
                'src_ip': packet.ip.src,
                'dst_ip': packet.ip.dst,
                'protocol': packet.transport_layer,
                'length': int(packet.length)
            }
            packets.append(packet_data)
        except AttributeError:
            continue
        
        if data_queue is not None:
            data_queue.put(packet_data)
    
    # After capture is done, put a stop signal
    data_queue.put(None)
    
    return packets  # Return packets for further processing

# Function to start the traffic capture thread
def start_capture(interface="Wi-Fi", duration=10, data_queue=None):
    capture_thread = threading.Thread(target=capture_traffic1, args=(interface, duration, data_queue))
    capture_thread.start()
    return capture_thread

# Save the captured traffic to a CSV file
def save_to_csv(dataframe, filename="traffic_data1.csv"):
    dataframe.to_csv(filename, index=False)
    print(f"Data saved to {filename}")

# Main program to capture and save traffic
if __name__ == "__main__":
    data_queue = queue.Queue()

    # Start capture
    capture_thread = start_capture(interface="Wi-Fi", duration=10, data_queue=data_queue)

    # Wait for capture to finish and collect packets
    captured_data = []
    while True:
        data = data_queue.get()
        if data is None:
            break  # Stop when None is received
        captured_data.append(data)

    # Convert the captured data to DataFrame and save it to CSV
    traffic_df = pd.DataFrame(captured_data)
    save_to_csv(traffic_df)

    capture_thread.join()  # Ensure the capture thread has completed
    main()