#!/usr/bin/env python3
"""
Script to set up Cognito User Pool for Enterprise IT Agent

This script creates a Cognito User Pool with authentication configuration
for the IT agents using the utility functions from utils.py.
"""

import json
import logging
import sys
import secrets
import string
from pathlib import Path
from typing import Dict, Optional

# Import utility functions
import sys
import os

# Add the parent directory (agents) to Python path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)

# Now import utils
from utils import setup_cognito_user_pool

def generate_secure_password(length=12):
    """
    Generate a secure random password.

    Args:
        length: Length of the password

    Returns:
        str: Randomly generated password
    """
    # Define character sets
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*"

    # Ensure at least one character from each set
    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(symbols)
    ]

    # Fill the rest randomly
    all_chars = lowercase + uppercase + digits + symbols
    password.extend(secrets.choice(all_chars) for _ in range(length - 4))

    # Shuffle the password
    password_list = list(password)
    secrets.SystemRandom().shuffle(password_list)
    return ''.join(password_list)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s,p%(process)s,{%(filename)s:%(lineno)d},%(levelname)s,%(message)s",
)
logger = logging.getLogger(__name__)


def save_cognito_config(
    cognito_config: Dict[str, str],
    output_file: str = "cognito_config.json"
) -> bool:
    """
    Save Cognito configuration to a JSON file
    
    Args:
        cognito_config: Dictionary containing Cognito configuration
        output_file: Path to output file
        
    Returns:
        bool: True if saved successfully, False otherwise
    """
    try:
        config_path = Path(output_file)
        logger.info(f"Saving Cognito configuration to {config_path}")
        
        with open(config_path, 'w') as f:
            json.dump(cognito_config, f, indent=2)
        
        logger.info(f"Successfully saved configuration to {config_path}")
        return True
    except Exception as e:
        logger.error(f"Error saving configuration: {e}")
        return False


def main():
    """
    Main function to set up Cognito User Pool for Enterprise IT agent
    """
    logger.info("Starting Cognito User Pool setup for Enterprise IT Agent")
    
    try:
        # Generate a secure password for demonstration
        demo_password = generate_secure_password()

        # Set up Cognito User Pool
        logger.info("Creating Cognito User Pool...")
        cognito_config = setup_cognito_user_pool()

        if cognito_config is None:
            logger.error("Failed to create Cognito User Pool")
            sys.exit(1)

        logger.info("✅ Successfully created Cognito User Pool")

        # Display the configuration
        logger.info("Cognito Configuration:")
        logger.info(f"Pool ID: {cognito_config['pool_id']}")
        logger.info(f"Client ID: {cognito_config['client_id']}")
        logger.info(f"Discovery URL: {cognito_config['discovery_url']}")
        logger.info(f"Bearer Token: {cognito_config['bearer_token'][:20]}...")

        # Save configuration to file
        if save_cognito_config(cognito_config):
            logger.info("✅ Configuration saved to cognito_config.json")
        else:
            logger.warning("⚠️ Failed to save configuration to file")

        # Print usage information
        print("\n" + "="*60)
        print("COGNITO SETUP COMPLETE")
        print("="*60)
        print(f"Pool ID: {cognito_config['pool_id']}")
        print(f"Client ID: {cognito_config['client_id']}")
        print(f"Discovery URL: {cognito_config['discovery_url']}")
        print(f"Username: ituser")
        print(f"Password: {demo_password}")
        print("="*60)
        print("Use these credentials to authenticate with the Enterprise IT agent")
        print("Configuration has been saved to cognito_config.json")
        print("="*60)
        print("⚠️  SECURITY NOTICE: The password shown above is randomly generated.")
        print("   Save it securely and do not commit it to version control.")
        print("   In production, use environment variables or AWS Secrets Manager.")
        
    except Exception as e:
        logger.error(f"Error during Cognito setup: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()