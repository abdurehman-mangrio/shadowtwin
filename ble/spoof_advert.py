import subprocess
import time

class BleSpoof:
    def __init__(self, name="ShadowTwin-AP", uuid="180F"):
        self.name = name
        self.uuid = uuid

    def start(self):
        print(f"[+] Starting BLE advertisement as '{self.name}' with UUID {self.uuid}")

        adv_data = f"0201060303{self.uuid}0C09{self.name.encode().hex()}"
        self.run_cmd("sudo hciconfig hci0 up")
        self.run_cmd("sudo hcitool -i hci0 cmd 0x08 0x0008 " + adv_data)
        self.run_cmd("sudo hcitool -i hci0 cmd 0x08 0x000a 01")

        print("[+] Advertisement started. Use `bluetoothctl scan on` to see it.")

        try:
            while True:
                time.sleep(10)
        except KeyboardInterrupt:
            self.stop()

    def run_cmd(self, cmd):
        try:
            subprocess.run(cmd.split(), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            print(f"[!] Failed to execute: {cmd}")

    def stop(self):
        self.run_cmd("sudo hcitool -i hci0 cmd 0x08 0x000a 00")
        print("[+] BLE advertisement stopped.")