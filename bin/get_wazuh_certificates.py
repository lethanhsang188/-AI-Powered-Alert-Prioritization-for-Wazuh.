#!/usr/bin/env python3
"""
Script to fetch SSL certificates from Wazuh API and Indexer servers.
This script connects to the servers and saves their certificates to local files.
"""
import os
import ssl
import socket
import sys
from urllib.parse import urlparse

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from dotenv import load_dotenv

# Load .env file
load_dotenv()

def get_certificate(hostname: str, port: int) -> str:
    """Fetch SSL certificate from a server."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
                return cert_pem
    except Exception as e:
        print(f"Error fetching certificate from {hostname}:{port}: {e}")
        raise

def save_certificate(cert_pem: str, filepath: str) -> None:
    """Save certificate to file."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w') as f:
        f.write(cert_pem)
    print(f"[OK] Certificate saved to: {filepath}")

def main():
    """Main function."""
    print("=" * 60)
    print("Wazuh Certificate Fetcher")
    print("=" * 60)
    
    # Get URLs from environment
    api_url = os.getenv("WAZUH_API_URL", "")
    indexer_url = os.getenv("WAZUH_INDEXER_URL", "")
    
    if not api_url:
        print("ERROR: WAZUH_API_URL not set in .env file")
        return 1
    
    # Parse URLs
    api_parsed = urlparse(api_url)
    api_host = api_parsed.hostname or "localhost"
    api_port = api_parsed.port or (443 if api_parsed.scheme == "https" else 80)
    
    if indexer_url:
        idx_parsed = urlparse(indexer_url)
        idx_host = idx_parsed.hostname or "localhost"
        idx_port = idx_parsed.port or (443 if idx_parsed.scheme == "https" else 80)
    else:
        # Derive from API URL
        idx_host = api_host
        idx_port = 9200 if api_port == 55000 else 9200
    
    base_dir = os.path.join(os.path.dirname(__file__), '..')
    cert_dir = os.path.join(base_dir, "cert wazuh")
    
    print(f"\nAPI Server: {api_host}:{api_port}")
    print(f"Indexer Server: {idx_host}:{idx_port}")
    print(f"Certificate Directory: {cert_dir}")
    print()
    
    # Fetch API certificate
    print("Fetching Wazuh API certificate...")
    try:
        api_cert = get_certificate(api_host, api_port)
        api_cert_path = os.path.join(cert_dir, "wazuh-api-server.crt")
        save_certificate(api_cert, api_cert_path)
    except Exception as e:
        print(f"[ERROR] Failed to fetch API certificate: {e}")
        return 1
    
    # Fetch Indexer certificate
    print("\nFetching Wazuh Indexer certificate...")
    try:
        idx_cert = get_certificate(idx_host, idx_port)
        idx_cert_path = os.path.join(cert_dir, "wazuh-indexer.crt")
        save_certificate(idx_cert, idx_cert_path)
    except Exception as e:
        print(f"[ERROR] Failed to fetch Indexer certificate: {e}")
        return 1
    
    print("\n" + "=" * 60)
    print("[SUCCESS] All certificates fetched successfully!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Update your .env file:")
    print("   WAZUH_API_VERIFY_SSL=true")
    print("   WAZUH_INDEXER_VERIFY_SSL=true")
    print("2. Restart the pipeline")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

