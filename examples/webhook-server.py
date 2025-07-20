#!/usr/bin/env python3
"""
Simple webhook receiver for testing GFWReport plugin
This server receives and logs threat events from the plugin
"""

import json
import logging
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/webhook-threats.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class WebhookHandler(BaseHTTPRequestHandler):
    """HTTP request handler for webhook endpoints"""
    
    def do_POST(self):
        """Handle POST requests from GFWReport plugin"""
        try:
            # Get content length
            content_length = int(self.headers.get('Content-Length', 0))
            
            # Read request body
            post_data = self.rfile.read(content_length)
            
            # Parse JSON data
            try:
                threat_data = json.loads(post_data.decode('utf-8'))
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON received: {e}")
                self.send_error(400, "Invalid JSON")
                return
            
            # Log the threat event
            self.log_threat_event(threat_data)
            
            # Process the threat (example)
            self.process_threat(threat_data)
            
            # Send success response
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            response = {
                "status": "success",
                "message": "Threat event processed",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            
            self.wfile.write(json.dumps(response).encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Error processing webhook: {e}")
            self.send_error(500, f"Internal server error: {str(e)}")
    
    def do_GET(self):
        """Handle GET requests for health checks"""
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            response = {
                "status": "healthy",
                "service": "GFWReport Webhook Receiver",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            
            self.wfile.write(json.dumps(response).encode('utf-8'))
        else:
            self.send_error(404, "Not found")
    
    def log_threat_event(self, threat_data):
        """Log threat event details"""
        logger.warning(
            f"THREAT DETECTED - "
            f"IP: {threat_data.get('ip', 'unknown')}, "
            f"Path: {threat_data.get('path', 'unknown')}, "
            f"UA: {threat_data.get('user_agent', 'unknown')}, "
            f"Method: {threat_data.get('method', 'unknown')}, "
            f"Type: {threat_data.get('threat_type', 'unknown')}"
        )
    
    def process_threat(self, threat_data):
        """Process threat event (example implementation)"""
        threat_type = threat_data.get('threat_type', 'unknown')
        ip = threat_data.get('ip', 'unknown')
        
        # Example processing based on threat type
        if threat_type == 'malicious_ip':
            logger.info(f"Processing malicious IP: {ip}")
            # Add to blocklist, send alert, etc.
            
        elif threat_type == 'malicious_path':
            path = threat_data.get('path', 'unknown')
            logger.info(f"Processing malicious path access: {path} from {ip}")
            # Log path-specific threat, analyze patterns, etc.
            
        elif threat_type == 'malicious_ua':
            ua = threat_data.get('user_agent', 'unknown')
            logger.info(f"Processing malicious user agent: {ua} from {ip}")
            # Analyze user agent patterns, update detection rules, etc.
        
        # Example: Save to database, send to SIEM, etc.
        self.save_to_database(threat_data)
    
    def save_to_database(self, threat_data):
        """Save threat data to database (example)"""
        # This is a placeholder for database integration
        logger.info("Threat data would be saved to database here")
        
        # Example database operations:
        # - Insert into threats table
        # - Update IP reputation scores
        # - Create incident tickets
        # - Update security dashboards
    
    def log_message(self, format, *args):
        """Override default log message to use our logger"""
        logger.info(f"{self.address_string()} - {format % args}")

def run_server(port=9090):
    """Run the webhook server"""
    server_address = ('', port)
    httpd = HTTPServer(server_address, WebhookHandler)
    
    logger.info(f"Starting webhook server on port {port}")
    logger.info("Endpoints:")
    logger.info("  POST / - Receive threat events")
    logger.info("  GET /health - Health check")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down webhook server")
        httpd.shutdown()

if __name__ == '__main__':
    run_server()
