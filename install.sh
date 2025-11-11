#!/bin/bash

# ShadowTwin Advanced - Installation Script
echo "[*] Installing ShadowTwin Advanced Evil Twin Framework"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[-] Please run as root for full functionality"
    exit 1
fi

# Check Python version
python3 --version >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[-] Python 3 is required but not installed"
    exit 1
fi

# Update system packages
echo "[*] Updating system packages..."
apt update && apt upgrade -y

# Install system dependencies
echo "[*] Installing system dependencies..."
apt install -y \
    python3-pip \
    python3-venv \
    hostapd \
    dnsmasq \
    iptables \
    net-tools \
    wireless-tools \
    airmon-ng \
    aircrack-ng \
    tshark \
    procps \
    usbutils \
    reaver \
    bully \
    wash \
    arpspoof \
    sslstrip \
    macchanger

# Create virtual environment
echo "[*] Creating Python virtual environment..."
python3 -m venv shadowtwin-env
source shadowtwin-env/bin/activate

# Install Python packages
echo "[*] Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Install the package in development mode
echo "[*] Installing ShadowTwin in development mode..."
pip install -e .

# Create necessary directories
echo "[*] Setting up directories..."
mkdir -p logs/sessions logs/credentials logs/packets logs/intelligence
mkdir -p assets/wordlists assets/certificates assets/payloads assets/icons
mkdir -p portals

# Download additional wordlists if needed
if [ ! -f "assets/wordlists/common_passwords.txt" ]; then
    echo "[*] Downloading common wordlists..."
    wget -O assets/wordlists/common_passwords.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt
fi

# Create default portal templates
echo "[*] Creating default portal templates..."
cat > portals/hotel_login.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hotel Guest WiFi</title>
    <style>
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); margin: 0; padding: 20px; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .login-container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); width: 100%; max-width: 400px; }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo h1 { color: #333; margin: 0; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; color: #555; font-weight: bold; }
        input[type="text"], input[type="password"], input[type="email"] { width: 100%; padding: 12px; border: 2px solid #ddd; border-radius: 5px; font-size: 16px; box-sizing: border-box; }
        input:focus { border-color: #667eea; outline: none; }
        .btn { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; padding: 15px; border-radius: 5px; font-size: 16px; cursor: pointer; width: 100%; font-weight: bold; }
        .btn:hover { opacity: 0.9; }
        .terms { text-align: center; margin-top: 20px; font-size: 12px; color: #666; }
        .message { padding: 10px; border-radius: 5px; margin-bottom: 20px; text-align: center; display: none; }
        .error { background: #ffebee; color: #c62828; border: 1px solid #ffcdd2; }
        .success { background: #e8f5e8; color: #2e7d32; border: 1px solid #c8e6c9; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>🏨 Hotel Guest WiFi</h1>
            <p>Connect to our premium WiFi service</p>
        </div>
        
        <div id="message" class="message"></div>
        
        <form id="loginForm">
            <div class="form-group">
                <label for="room">Room Number:</label>
                <input type="text" id="room" name="room" required>
            </div>
            
            <div class="form-group">
                <label for="lastname">Last Name:</label>
                <input type="text" id="lastname" name="lastname" required>
            </div>
            
            <div class="form-group">
                <label for="email">Email Address:</label>
                <input type="email" id="email" name="email" required>
            </div>
            
            <button type="submit" class="btn">Connect to WiFi</button>
        </form>
        
        <div class="terms">
            By connecting, you agree to our Terms of Service and Privacy Policy.
            Unauthorized access is prohibited.
        </div>
    </div>

    <script>
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const room = document.getElementById('room').value;
            const lastname = document.getElementById('lastname').value;
            const email = document.getElementById('email').value;
            
            const btn = document.querySelector('.btn');
            btn.textContent = 'Connecting...';
            btn.disabled = true;
            
            setTimeout(() => {
                const messageDiv = document.getElementById('message');
                messageDiv.textContent = 'Success! You are now connected to the WiFi.';
                messageDiv.className = 'message success';
                messageDiv.style.display = 'block';
                
                setTimeout(() => {
                    window.location.href = 'http://www.google.com';
                }, 2000);
            }, 2000);
        });
    </script>
</body>
</html>
EOF

# Set permissions
echo "[*] Setting permissions..."
chmod +x main.py
chmod +x install.sh
chmod 600 config.yaml
chmod -R 700 logs/
chmod -R 700 assets/

# Create configuration file
echo "[*] Creating default configuration..."
cat > config.yaml << 'EOF'
# ShadowTwin Advanced Configuration
core:
  log_level: INFO
  max_sessions: 10
  session_timeout: 3600

network:
  monitor_interface: wlan0
  attack_interface: wlan1
  default_channel: 6
  country_code: US

captive_portal:
  default_template: hotel_login
  ssl_enabled: false
  port: 8080
  redirect_url: http://www.google.com

attacks:
  deauth_enabled: true
  deauth_packets: 10
  beacon_interval: 0.1
  wps_timeout: 120

evasion:
  mac_rotation: true
  rotation_interval: 300
  ssid_morphing: false

logging:
  encrypt_logs: true
  log_retention_days: 30
EOF

echo "[+] Installation completed successfully!"
echo "[+] Activate virtual environment: source shadowtwin-env/bin/activate"
echo "[+] Run: python main.py --help"
echo "[+] Available commands: recon, attack, deauth, beacon, wps, post, auto"