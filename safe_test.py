from pathlib import Path
import time

folder = Path(r"C:\Users\maha\RansomwareTest\SafeTest")
folder.mkdir(exist_ok=True)

files = []

for i in range(1, 21):
    file = folder / f"hold_test_{i}.txt"

    f = open(file, "w", encoding="utf-8")
    f.write("Safe ransomware detection test\n")
    f.flush()

    files.append(f)
    print(f"Created and kept open: {file.name}")
    time.sleep(0.2)

print("20 files are OPEN. Do not close this window.")
time.sleep(15)

for f in files:
    f.close()

print("Test finished.")