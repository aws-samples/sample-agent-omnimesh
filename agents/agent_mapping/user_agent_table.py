"""
User-Agent Mapping Table Management

This module provides functionality to create, view, and edit a table that maps
users to available agents using DynamoDB. The table shows:
- User/Service names (e.g., infrastructure_team, development_team, database_admin)
- Enabled Agents (list of agents that user can access)

The table can be displayed in a formatted view and edited interactively.
"""
import json
import yaml
import argparse
import boto3
import os
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
from botocore.exceptions import ClientError

# this is the name of the table that will be created
DEFAULT_TABLE_NAME: str = "enterprise-it-agent-mappings"
# this yaml file consists of the product mapping information
DEFAULT_YAML_FILE: str = "plug_in_mapping.yaml"
DEFAULT_AWS_REGION: str = "us-west-2"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s,p%(process)s,{%(filename)s:%(lineno)d},%(levelname)s,%(message)s",
)

class UserAgentTable:
    """Manages user-agent mapping table operations using DynamoDB."""

    def __init__(
        self,
        table_name: str = DEFAULT_TABLE_NAME,
        aws_region: str = DEFAULT_AWS_REGION,
        yaml_file: Optional[str] = None
    ):
        self.table_name = table_name
        self.aws_region = aws_region
        self.yaml_file = yaml_file
        self.logger = logging.getLogger(__name__)

        # Initialize DynamoDB resource
        self.dynamodb = boto3.resource('dynamodb', region_name=self.aws_region)
        self.table = None

        # Ensure table exists
        self._ensure_table_exists()

    def _ensure_table_exists(self) -> None:
        """Create DynamoDB table if it doesn't exist."""
        try:
            # Try to access the table
            self.table = self.dynamodb.Table(self.table_name)
            self.table.load()
            self.logger.info(f"Connected to existing DynamoDB table: {self.table_name}")
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                self.logger.info(f"Table {self.table_name} not found. Creating...")
                self._create_table()
            else:
                raise

    def _create_table(self) -> None:
        """Create DynamoDB table with appropriate schema."""
        try:
            self.table = self.dynamodb.create_table(
                TableName=self.table_name,
                KeySchema=[
                    {
                        'AttributeName': 'user_id',
                        'KeyType': 'HASH'
                    }
                ],
                AttributeDefinitions=[
                    {
                        'AttributeName': 'user_id',
                        'AttributeType': 'S'
                    }
                ],
                BillingMode='PAY_PER_REQUEST'
            )

            # Wait for table to be created
            self.logger.info("Waiting for table to be created...")
            self.table.wait_until_exists()
            self.logger.info(f"Successfully created DynamoDB table: {self.table_name}")

        except ClientError as e:
            self.logger.error(f"Failed to create table: {e}")
            raise

    def _migrate_from_yaml(self) -> None:
        """Migrate data from YAML file to DynamoDB if YAML file exists."""
        if not self.yaml_file:
            return

        yaml_path = Path(self.yaml_file)
        if not yaml_path.exists():
            return

        self.logger.info(f"Migrating data from {self.yaml_file} to DynamoDB...")

        with open(yaml_path, "r") as f:
            data = yaml.safe_load(f) or {}

        plugin_products = data.get("plugin_products", {})

        for user_id, agents in plugin_products.items():
            self.add_user(user_id, agents)

        self.logger.info(f"Successfully migrated {len(plugin_products)} users to DynamoDB")

    def save_data(self) -> None:
        """Save data back to YAML file (for backward compatibility)."""
        if not self.yaml_file:
            self.logger.info("No YAML file specified for backup")
            return

        # Export all data from DynamoDB
        all_data = {"plugin_products": {}}

        try:
            response = self.table.scan()
            items = response.get('Items', [])

            # Handle pagination
            while 'LastEvaluatedKey' in response:
                response = self.table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
                items.extend(response.get('Items', []))

            for item in items:
                all_data["plugin_products"][item['user_id']] = item.get('enabled_agents', [])

            with open(self.yaml_file, "w") as f:
                yaml.dump(all_data, f, default_flow_style=False, sort_keys=True)
            self.logger.info(f"Data backed up to {self.yaml_file}")

        except ClientError as e:
            self.logger.error(f"Failed to backup data to YAML: {e}")
            raise

    def display_table(self) -> None:
        """Display the user-agent mapping table in a formatted view."""
        try:
            response = self.table.scan()
            items = response.get('Items', [])

            # Handle pagination
            while 'LastEvaluatedKey' in response:
                response = self.table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
                items.extend(response.get('Items', []))

            if not items:
                print("No user-agent mappings found.")
                return

            # Convert to dict format for compatibility
            plugin_products = {}
            for item in items:
                plugin_products[item['user_id']] = item.get('enabled_agents', [])

            # Calculate column widths
            max_user_width = max(len("User/Product"), max(len(user) for user in plugin_products.keys()))
            max_agents_width = max(len("Enabled Agents"),
                                  max(len(", ".join(agents)) for agents in plugin_products.values()))

            # Print header
            print("=" * (max_user_width + max_agents_width + 7))
            print(f"| {'User/Product':<{max_user_width}} | {'Enabled Agents':<{max_agents_width}} |")
            print("=" * (max_user_width + max_agents_width + 7))

            # Print data rows
            for user, agents in sorted(plugin_products.items()):
                agents_str = ", ".join(agents) if isinstance(agents, list) else str(agents)
                print(f"| {user:<{max_user_width}} | {agents_str:<{max_agents_width}} |")

            print("=" * (max_user_width + max_agents_width + 7))
            print(f"Total users: {len(plugin_products)}")

        except ClientError as e:
            self.logger.error(f"Failed to display table: {e}")
            raise

    def add_user(self, user: str, agents: List[str]) -> None:
        """Add a new user with enabled agents."""
        try:
            self.table.put_item(
                Item={
                    'user_id': user,
                    'enabled_agents': agents
                }
            )
            print(f"[info] Added user '{user}' with agents: {', '.join(agents)}")

        except ClientError as e:
            self.logger.error(f"Failed to add user '{user}': {e}")
            raise

    def remove_user(self, user: str) -> None:
        """Remove a user from the table."""
        try:
            response = self.table.delete_item(
                Key={'user_id': user},
                ReturnValues='ALL_OLD'
            )

            if 'Attributes' in response:
                print(f"[info] Removed user '{user}'")
            else:
                print(f"[warning] User '{user}' not found")

        except ClientError as e:
            self.logger.error(f"Failed to remove user '{user}': {e}")
            raise

    def update_user_agents(self, user: str, agents: List[str]) -> None:
        """Update agents for an existing user."""
        try:
            response = self.table.update_item(
                Key={'user_id': user},
                UpdateExpression='SET enabled_agents = :agents',
                ExpressionAttributeValues={':agents': agents},
                ReturnValues='UPDATED_NEW'
            )

            if 'Attributes' in response:
                print(f"[info] Updated agents for user '{user}': {', '.join(agents)}")
            else:
                print(f"[warning] User '{user}' not found. Use add_user to create new user.")

        except ClientError as e:
            self.logger.error(f"Failed to update user '{user}': {e}")
            raise

    def get_user_agents(self, user: str) -> Optional[List[str]]:
        """Get agents for a specific user."""
        try:
            response = self.table.get_item(Key={'user_id': user})

            if 'Item' in response:
                return response['Item'].get('enabled_agents', [])
            return None

        except ClientError as e:
            self.logger.error(f"Failed to get user agents for '{user}': {e}")
            raise

    def list_all_agents(self) -> List[str]:
        """Get a sorted list of all unique agents across all users."""
        try:
            response = self.table.scan()
            items = response.get('Items', [])

            # Handle pagination
            while 'LastEvaluatedKey' in response:
                response = self.table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
                items.extend(response.get('Items', []))

            all_agents = set()
            for item in items:
                agents = item.get('enabled_agents', [])
                if isinstance(agents, list):
                    all_agents.update(agents)

            return sorted(all_agents)

        except ClientError as e:
            self.logger.error(f"Failed to list all agents: {e}")
            raise

    def interactive_edit(self) -> None:
        """Interactive editing mode for the table."""
        while True:
            print("\n" + "="*50)
            print("USER-AGENT TABLE EDITOR")
            print("="*50)
            print("1. Display table")
            print("2. Add user")
            print("3. Update user agents")
            print("4. Remove user")
            print("5. List all available agents")
            print("6. Save and exit")
            print("7. Exit without saving")

            choice = input("\nEnter your choice (1-7): ").strip()

            if choice == "1":
                print("\n")
                self.display_table()

            elif choice == "2":
                user = input("Enter user/product name: ").strip()
                if not user:
                    print("[error] User name cannot be empty")
                    continue

                print("Available agents:", ", ".join(self.list_all_agents()))
                agents_input = input("Enter agents (comma-separated): ").strip()
                agents = [agent.strip() for agent in agents_input.split(",") if agent.strip()]

                if agents:
                    self.add_user(user, agents)
                else:
                    print("[error] At least one agent must be specified")

            elif choice == "3":
                user = input("Enter user/product name to update: ").strip()
                current_agents = self.get_user_agents(user)

                if current_agents is None:
                    print(f"[error] User '{user}' not found")
                    continue

                print(f"Current agents for '{user}': {', '.join(current_agents)}")
                print("Available agents:", ", ".join(self.list_all_agents()))
                agents_input = input("Enter new agents (comma-separated): ").strip()
                agents = [agent.strip() for agent in agents_input.split(",") if agent.strip()]

                if agents:
                    self.update_user_agents(user, agents)
                else:
                    print("[error] At least one agent must be specified")

            elif choice == "4":
                user = input("Enter user/product name to remove: ").strip()
                confirm = input(f"Are you sure you want to remove '{user}'? (y/N): ").strip().lower()
                if confirm == "y":
                    self.remove_user(user)

            elif choice == "5":
                agents = self.list_all_agents()
                print(f"\nAll available agents ({len(agents)}):")
                for agent in agents:
                    print(f"  - {agent}")

            elif choice == "6":
                self.save_data()
                print("[info] Changes saved. Exiting...")
                break

            elif choice == "7":
                confirm = input("Exit without saving changes? (y/N): ").strip().lower()
                if confirm == "y":
                    print("[info] Exiting without saving...")
                    break

            else:
                print("[error] Invalid choice. Please enter 1-7.")


def _parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Manage user-agent mapping table using DynamoDB",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Display current table
    python user_agent_table.py --display

    # Interactive editing mode
    python user_agent_table.py --edit

    # Export to JSON
    python user_agent_table.py --export output.json

    # Use custom table name and region
    python user_agent_table.py --table-name my-table --region us-east-1 --display

    # Migrate from YAML file to DynamoDB
    python user_agent_table.py --migrate-from-yaml mapping.yaml
"""
    )

    parser.add_argument(
        "--table-name",
        default=DEFAULT_TABLE_NAME,
        help=f"DynamoDB table name (default: {DEFAULT_TABLE_NAME})"
    )

    parser.add_argument(
        "--region",
        default=DEFAULT_AWS_REGION,
        help=f"AWS region (default: {DEFAULT_AWS_REGION})"
    )

    parser.add_argument(
        "--yaml",
        help="YAML file for backup/export operations"
    )

    parser.add_argument(
        "--migrate-from-yaml",
        help="Migrate data from YAML file to DynamoDB"
    )

    parser.add_argument(
        "--display",
        action="store_true",
        help="Display the current table"
    )

    parser.add_argument(
        "--edit",
        action="store_true",
        help="Enter interactive editing mode"
    )

    parser.add_argument(
        "--export",
        help="Export table to JSON file"
    )

    parser.add_argument(
        "--list-agents",
        action="store_true",
        help="List all unique agents"
    )

    return parser.parse_args()


def main():
    """Main function to handle command line operations."""
    args = _parse_args()

    try:
        # Initialize table with DynamoDB configuration
        table = UserAgentTable(
            table_name=args.table_name,
            aws_region=args.region,
            yaml_file=args.yaml
        )

        if args.migrate_from_yaml:
            # Override yaml_file for migration
            table.yaml_file = args.migrate_from_yaml
            table._migrate_from_yaml()

        elif args.display:
            table.display_table()

        elif args.edit:
            table.interactive_edit()

        elif args.export:
            # Export all data from DynamoDB
            response = table.table.scan()
            items = response.get('Items', [])

            # Handle pagination
            while 'LastEvaluatedKey' in response:
                response = table.table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
                items.extend(response.get('Items', []))

            # Convert to plugin_products format for export
            export_data = {"plugin_products": {}}
            for item in items:
                export_data["plugin_products"][item['user_id']] = item.get('enabled_agents', [])

            with open(args.export, "w") as f:
                json.dump(export_data, f, indent=2)
            print(f"[info] Table exported to {args.export}")

        elif args.list_agents:
            agents = table.list_all_agents()
            print(f"All available agents ({len(agents)}):")
            for agent in agents:
                print(f"  - {agent}")

        else:
            # Default action: display table
            table.display_table()

    except Exception as e:
        print(f"[error] {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())