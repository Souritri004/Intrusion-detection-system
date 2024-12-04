# Intrusion-detection-system
This project captures real-time network traffic from a specified network interface (e.g., Wi-Fi) using the `pyshark` library, and performs anomaly detection on the captured packets. It uses multi-threading to efficiently capture and analyze packets concurrently. 

The key features of this project include:
1. **Real-time Traffic Capture**: It continuously captures network packets from the specified interface using `pyshark.LiveCapture`.
2. **Anomaly Detection**: The program checks for specific anomalies such as unusually large packets or unexpected source/destination IP addresses.
3. **Threaded Processing**: It employs multiple threads, one for capturing the packets and another for analyzing and detecting anomalies, allowing for concurrent execution without blocking.
4. **Data Export**: The processed data, including any detected anomalies, can be saved into a CSV file for further offline analysis.
   
The project is built with Python and makes use of several libraries, including `pyshark`, `pandas`, `asyncio`, and `threading`. The use of threading ensures that the capture process runs in the background while the data is being processed, making it suitable for real-time network monitoring.
