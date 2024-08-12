import hashlib

def detect_thread(rfid_data):
    """
    Detect potential threats in RFID communication.
    Args:
        rfid_data (list): List of RFID data points (e.g., signal strength, frequency).

    Returns:
        bool: True if a threat is detected, False otherwise.
    """
    # Extract relevant features from RFID data
    signal_strength = extract_signal_strength(rfid_data)
    frequency_deviation = extract_frequency_deviation(rfid_data)

    # Set thresholds for anomaly detection
    signal_strength_threshold = float(input("Enter the signal strength threshold value :")) # Example threshold (adjust as needed)
    frequency_deviation_threshold = float(input("Enter the frequency deviation threshold value :"))  # Example threshold (adjust as needed)

    # Check for anomalies
    if signal_strength < signal_strength_threshold and signal_strength_threshold == 13.56 :
        return False  # Low signal strength indicates potential tampering

    if abs(frequency_deviation) > frequency_deviation_threshold and frequency_deviation_threshold == 0.7:
        return False  # Abnormal frequency deviation suggests an attack

    return True  # No threat detected

def extract_signal_strength(rfid_data):
    # Extract and normalize signal strength from RFID data
    # Example implementation: Calculate average signal strength
    return sum(rfid_data) / len(rfid_data)

def extract_frequency_deviation(rfid_data):
    # Extract and calculate frequency deviation from RFID data
    # Example implementation: Compare current frequency with expected frequency
    expected_frequency = 13.56  # Example expected frequency in MHz
    current_frequency = calculate_current_frequency(rfid_data)
    return current_frequency - expected_frequency

def calculate_current_frequency(rfid_data):
    # Example implementation: Analyze frequency components in the data
    # You may need to use Fourier transform or other techniques
    # to estimate the current frequency.
    return sum(rfid_data) / len(rfid_data)

def generate_sha256_hash(rfid_data):
    # Generate SHA-256 hash of RFID data
    sha256_hash = hashlib.sha256(str(rfid_data).encode()).hexdigest()
    return sha256_hash

# Example usage
rfid_data_points = [0.6,0.3,0.5]  # Example signal strength values
threat_detected = detect_thread(rfid_data_points)
if(threat_detected!=True):
    print(f"Threat detected: {threat_detected}")
    sha256_hash = generate_sha256_hash(rfid_data_points)
    print(f"SHA-256 Hash: {sha256_hash}")
else:
    print(f"Threat detected: {threat_detected}")