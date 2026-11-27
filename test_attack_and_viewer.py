import requests
import time

URL = "http://127.0.0.1:5000/capture"
headers_valid = {"Authorization": "Bearer ZT-CAM-LIVE-2026"}

print("\n--- TEST 1: AUTHORIZED FRONT CAMERA CAPTURE ---")
r1 = requests.get(URL, headers=headers_valid)
print("Status:", r1.status_code, "| Response:", r1.json())

time.sleep(1)

print("\n--- TEST 2: HACKER BRUTE-FORCE ATTACK ---")
for pwd in ["admin123", "root_cam", "pass2026"]:
    r = requests.get(URL, headers={"Authorization": f"Bearer {pwd}"})
    print(f"Attempt [{pwd}] -> Status: {r.status_code} | {r.json()}")
    time.sleep(1)

print("\n--- TEST 3: VERIFY IP QUARANTINE ---")
r3 = requests.get(URL, headers=headers_valid)
print("After Ban Status:", r3.status_code, "| Response:", r3.json())
