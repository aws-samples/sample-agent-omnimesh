#!/usr/bin/env python3
"""
Script to set up Cognito User Pool for the AgentCore gateway that will be used as a single
entry point to agents that will reside in this gateway as tools.
"""

import json
import logging
import sys
from pathlib import Path
from typing import Dict, Optional

# Import utility functions
import sys
import os

# Add the parent directory (agent_gateway) to Python path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)

# Now import utils
from utils import setup_cognito_user_pool

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
    Main function to set up Cognito User Pool for Enterprise IT Gateway
    """
    logger.info("Starting Cognito User Pool setup for Enterprise IT Gateway")
    
    try:
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
        print(f"Password: MyPassword123!")
        print("="*60)
        print("Use these credentials to authenticate with the Enterprise IT Gateway")
        print("Configuration has been saved to cognito_config.json")
        print("="*60)
        
    except Exception as e:
        logger.error(f"Error during Cognito setup: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()