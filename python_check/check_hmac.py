import hmac
import hashlib

# === CONFIGURE THESE ===
device_secret = b"9ur3Gwzk4zzLHuwR"
firmware_path = r"D:\Embedded\esp\esp32_with_tuya\build\esp32_with_tuya.bin"

with open(firmware_path, "rb") as f:
    firmware_data = f.read()

digest = hmac.new(device_secret, firmware_data, hashlib.sha256).hexdigest()
print("Calculated HMAC:", digest)
