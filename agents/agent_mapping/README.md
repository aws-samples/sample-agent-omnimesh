# User-Agent Mapping Table

This directory contains tools for managing user-agent mappings using DynamoDB that define which agents are available to different users/services in the Enterprise IT ecosystem.

## Overview

The user-agent mapping system uses DynamoDB as the primary data store and provides:

- **DynamoDB Table Management**: Automatic creation and management of user-agent mappings table
- **Interactive Editor**: `user_agent_table.py` - Command-line tool to view and edit mappings
- **YAML Migration**: Support for migrating from legacy YAML files to DynamoDB
- **Export Capabilities**: Export data to JSON or backup to YAML files

## Table Structure

The DynamoDB table stores:
- **user_id** (Primary Key): Service names like `infrastructure_team`, `development_team`, `database_admin`
- **enabled_agents**: List of agents that user can access (e.g., `ServiceDesk`, `Infrastructure`, `DevelopmentTools`)

Example data structure:
```json
{
  "infrastructure_team": ["ServiceDesk", "Infrastructure"],
  "development_team": ["ServiceDesk", "DevelopmentTools"],
  "database_admin": ["ServiceDesk", "Database"]
}
```

## Prerequisites

- Python 3.11+
- AWS credentials configured with DynamoDB permissions
- Required packages: `boto3`, `pyyaml`

## Installation

Install required dependencies:
```bash
uv add boto3 pyyaml
```

Or using pip:
```bash
pip install boto3 pyyaml
```

## Quick Start

### Display Current Table

View the current user-agent mappings (creates table if it doesn't exist):

```bash
python user_agent_table.py --display
```

Output example:
```
===============================================
| User/Service                 | Enabled Agents                 |
===============================================
| infrastructure_team         | ServiceDesk, Infrastructure     |
| development_team            | ServiceDesk, DevelopmentTools   |
| database_admin              | ServiceDesk, Database           |
===============================================
Total users: 3
```

### Default Configuration

By default, the tool uses:
- **Table Name**: `user-agent-mappings`
- **AWS Region**: `us-west-2`
- Creates table automatically if it doesn't exist

## Usage

### Interactive Editing Mode

Enter interactive mode to add, update, or remove user-agent mappings:

```bash
python user_agent_table.py --edit
```

This provides a menu-driven interface with options to:
1. Display table
2. Add user
3. Update user agents
4. Remove user
5. List all available agents
6. Save and exit
7. Exit without saving

### Export to JSON

Export the current mappings to a JSON file:

```bash
python user_agent_table.py --export output.json
```

### List All Agents

See all unique agents across all users:

```bash
python user_agent_table.py --list-agents
```

### Custom Configuration

Use custom table name and region:

```bash
python user_agent_table.py --table-name my-user-mappings --region us-east-1 --display
```

### Migrate from YAML File

Import existing YAML configuration into DynamoDB:

```bash
python user_agent_table.py --migrate-from-yaml plug_in_mapping.yaml
```

### Backup to YAML

Export current DynamoDB data to YAML file:

```bash
python user_agent_table.py --yaml backup.yaml --display
# Then use save option in interactive mode to write to YAML
```

## Data Formats

### DynamoDB Table Schema

The table uses:
- **Primary Key**: `user_id` (String) - Product/user identifier
- **Attribute**: `enabled_agents` (List) - Array of agent names

### YAML Format (for migration/backup)

```yaml
plugin_products:
  user_name_1: ['Agent1', 'Agent2', 'Agent3']
  user_name_2: ['Agent1', 'Agent4']
  user_name_3: ['Default']
```

Where:
- `user_name_*`: Product or user identifier
- Agent list: Array of agent names this user can access

## Common Agent Types

Based on the current configuration, common agents include:
- `ServiceDesk` - Base agent available to all users for general IT support
- `Infrastructure` - Cloud infrastructure, networking, and server management agent
- `DevelopmentTools` - CI/CD, GitHub, Docker, Kubernetes agent
- `Database` - Database management and query optimization agent

## Command Line Options

All available options:

```bash
python user_agent_table.py [OPTIONS]

Options:
  --table-name TEXT     DynamoDB table name (default: user-agent-mappings)
  --region TEXT         AWS region (default: us-west-2)
  --yaml TEXT          YAML file for backup/export operations
  --migrate-from-yaml TEXT  Migrate data from YAML file to DynamoDB
  --display            Display the current table (default action)
  --edit               Enter interactive editing mode
  --export TEXT        Export table to JSON file
  --list-agents        List all unique agents
```

## File Structure

```
agent_mapping/
├── user_agent_table.py           # Main DynamoDB table management tool
├── plugin_products_table.py      # Alternative DynamoDB routing table tool
├── plug_in_mapping.yaml          # Optional YAML configuration (for migration)
└── README.md                     # This documentation
```

## Examples

### Adding a New User

1. Run interactive mode: `python user_agent_table.py --edit`
2. Choose option 2 (Add user)
3. Enter user name: `security_team`
4. Enter agents: `ServiceDesk, Infrastructure, Database`
5. Choose option 6 (Save and exit)

### Updating User Agents

1. Run interactive mode: `python user_agent_table.py --edit`
2. Choose option 3 (Update user agents)
3. Enter user name to update: `infrastructure_team`
4. Enter new agents: `ServiceDesk, Infrastructure, DevelopmentTools`
5. Choose option 6 (Save and exit)

### Batch Operations

For bulk changes, you can directly edit the `plug_in_mapping.yaml` file and then verify with:

```bash
python user_agent_table.py --display
```

## AWS Configuration

### Required AWS Permissions

Your AWS credentials need the following DynamoDB permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "dynamodb:CreateTable",
                "dynamodb:DescribeTable",
                "dynamodb:PutItem",
                "dynamodb:GetItem",
                "dynamodb:UpdateItem",
                "dynamodb:DeleteItem",
                "dynamodb:Scan"
            ],
            "Resource": "arn:aws:dynamodb:*:*:table/user-agent-mappings*"
        }
    ]
}
```

### Configure AWS Credentials

Set up AWS credentials using one of these methods:

```bash
# AWS CLI
aws configure

# Environment variables
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-west-2

# AWS credentials file
cat ~/.aws/credentials
[default]
aws_access_key_id = your_access_key
aws_secret_access_key = your_secret_key
```

## Error Handling

The tool handles common scenarios:
- **Missing DynamoDB table**: Automatically creates table with proper schema
- **AWS credentials not configured**: Shows clear error message
- **Non-existent users**: Shows warning when trying to update/remove
- **Empty agent lists**: Shows error and prevents invalid data
- **Network/AWS issues**: Displays detailed error messages with suggestions

## Troubleshooting

### Common Issues

1. **AWS credentials not found**
   ```
   Error: Unable to locate credentials
   Solution: Configure AWS credentials (see AWS Configuration section)
   ```

2. **Access denied to DynamoDB**
   ```
   Error: User is not authorized to perform dynamodb:CreateTable
   Solution: Add required DynamoDB permissions to your AWS user/role
   ```

3. **Table already exists with different schema**
   ```
   Error: Table exists but has different key schema
   Solution: Use different table name or delete existing table
   ```

## Development

To extend functionality:
1. Modify the `UserAgentTable` class in `user_agent_table.py`
2. Add new command-line options in `_parse_args()`
3. Test changes with: `python user_agent_table.py --display`

## Integration Notes

This user-agent mapping system integrates with:
- **Amazon Bedrock AgentCore**: For agent routing and access control
- **AWS DynamoDB**: Primary data store for user-agent mappings
- **Agent gateway systems**: For request routing based on user permissions
- **Authentication/authorization systems**: For access control validation