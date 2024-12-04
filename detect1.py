import threading  # Ensure threading is imported
import pandas as pd
import numpy as np

class AnomalyDetector:
    def init(self, traffic_data):
        self.traffic_data = traffic_data
    
    def calculate_baseline(self):
        # Calculate the mean and standard deviation of packet length
        self.mean_length = np.mean(self.traffic_data['length'])
        self.std_length = np.std(self.traffic_data['length'])
        print(f"Baseline - Mean Length: {self.mean_length}, Std Dev: {self.std_length}")
    
    def detect_anomalies(self, threshold=3):
        # Flag packets that are more than 'threshold' standard deviations away from the mean
        anomalies = self.traffic_data[np.abs(self.traffic_data['length'] - self.mean_length) > threshold * self.std_length]
        return anomalies

def anomaly_detection_thread(data_queue, detector):
    while True:
        packet = data_queue.get()
        if packet is None:
            break  # Stop if None is received (indicating capture is done)

        # Update the traffic data and detect anomalies
        detector.traffic_data = pd.DataFrame([packet])  # Just use the current packet for simplicity
        anomalies = detector.detect_anomalies(threshold=3)

        if not anomalies.empty:
            print(f"Anomalies detected: {anomalies}")
        else:
            print("No anomalies detected.")

# Start detection thread
def start_detection(data_queue):
    detector = AnomalyDetector(pd.DataFrame())
    detection_thread = threading.Thread(target=anomaly_detection_thread, args=(data_queue, detector))
    detection_thread.start()
    return detection_thread