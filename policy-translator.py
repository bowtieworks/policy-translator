import argparse
import json
import requests
import yaml
import os
import getpass
from urllib.parse import urlparse
import uuid
import re
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DynamicAPIClient:
    def __init__(self, session, base_url, openapi_spec):
        self.session = session
        self.base_url = base_url
        self.spec = openapi_spec
        self._create_api_methods()

    def _create_api_methods(self):
        for path, path_item in self.spec['paths'].items():
            for method, operation in path_item.items():
                if method in ['get', 'post', 'put', 'delete']:
                    operation_id = operation.get('operationId')
                    if operation_id:
                        setattr(self, operation_id, self._create_api_call(method, path, operation))

    def _create_api_call(self, method, path, operation):
        def api_call(**kwargs):
            url = f"{self.base_url}{path}"
            for param in operation.get('parameters', []):
                if param['in'] == 'path':
                    url = url.replace(f"{{{param['name']}}}", kwargs.pop(param['name']))
            
            request_kwargs = {}
            if 'requestBody' in operation:
                content_type = next(iter(operation['requestBody']['content']))
                if content_type == 'application/json':
                    request_kwargs['json'] = kwargs
                else:
                    request_kwargs['data'] = kwargs
            
            response = getattr(self.session, method)(url, **request_kwargs)
            try:
                response.raise_for_status()
            except requests.exceptions.HTTPError as e:
                logger.error(f"Error response from API: {response.status_code}")
                logger.error(f"Response content: {response.text}")
                raise e
            return response.json() if response.text else None
        
        return api_call

def load_yaml_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        logger.warning(f"Warning: File {file_path} not found. Skipping.")
        return {}
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML file {file_path}: {e}")
        return {}

def create_session(base_url, email, password):
    session = requests.Session()
    login_url = f"{base_url}/-net/api/v0/user/login"
    try:
        response = session.post(login_url, json={"email": email, "password": password})
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to create session: {e}")
        raise
    return session

def get_openapi_spec(session, base_url):
    spec_url = f"{base_url}/-net/api/v0/openapi.json"
    try:
        response = session.get(spec_url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to retrieve OpenAPI spec: {e}")
        raise
    return response.json()

def parse_port(port_string):
    try:
        port, protocol = port_string.split('/')
        return int(port), protocol
    except ValueError:
        logger.error(f"Invalid port string format: {port_string}")
        raise ValueError(f"Invalid port string format: {port_string}")

def clean_destination(dst):
    if dst.startswith('fqdn--'):
        return dst.split('--', 1)[1]
    elif dst.startswith('group--'):
        return dst.split('--', 1)[1]
    return dst

def create_collection(api_client, name, dry_run=True):
    collection = {
        "id": str(uuid.uuid4()),
        "name": name,
        "description": f"Collection for {name}",
        "members": []
    }
    logger.info(f"Creating collection: {json.dumps(collection, indent=2)}")
    if not dry_run:
        return api_client.upsert_collection(**collection)
    return collection

def add_members_to_collection(api_client, collection_id, members, dry_run=True):
    request = {
        "collection_id": collection_id,
        "members": members
    }
    logger.info(f"Adding members to collection: {json.dumps(request, indent=2)}")
    if not dry_run:
        return api_client.add_members_to_collection(**request)
    return request

def create_resource_from_collection(api_client, collection_id, name, ports, dry_run=True):
    parsed_ports = [parse_port(port) for port in ports]
    resource = {
        "id": str(uuid.uuid4()),
        "name": name,
        "protocol": parsed_ports[0][1] if parsed_ports else "tcp",
        "location": {"type": "collection", "value": collection_id},
        "ports": {"collection": {"ports": [port[0] for port in parsed_ports]}}
    }
    logger.info(f"Creating resource from collection: {json.dumps(resource, indent=2)}")
    if not dry_run:
        return api_client.upsert_resource(**resource)
    return resource

def create_policies(api_client, yaml_data, dry_run=True):
    user_groups = []
    resources = []
    resource_groups = []
    collections = []
    policies = []

    # Create user groups based on imports
    for import_file in yaml_data.get('imports', []):
        if import_file.startswith('groups/'):
            group_name = os.path.splitext(os.path.basename(import_file))[0]
            user_group = {
                "id": str(uuid.uuid4()),
                "name": group_name
            }
            logger.info(f"Creating user group: {json.dumps(user_group, indent=2)}")
            if not dry_run:
                created_user_group = api_client.upsert_group(**user_group)
                user_groups.append(created_user_group)
            else:
                user_groups.append(user_group)

    # Create resources, resource groups, and collections
    for rule in yaml_data.get('rules', []):
        rule_name = re.sub(r'\s+', '-', rule['name'].lower())
        resource_group = {
            "id": str(uuid.uuid4()),
            "name": rule_name,
            "inherited": [],
            "resources": []
        }

        for dst in rule.get('dst', []):
            clean_dst = clean_destination(dst)
            if clean_dst.endswith('.ad_hosts'):
                collection_name = clean_dst.split('.')[0]
                collection = create_collection(api_client, collection_name, dry_run)
                collections.append(collection)
                
                # TEST SECTION: Add 4 dummy IP addresses as members
                # TODO: Replace this with actual data from corresponding YAML file
                test_members = [
                    {"id": str(uuid.uuid4()), "name": f"Test IP {i}", "comment": "Test member", 
                     "location": {"type": "ip", "value": f"192.168.1.{i}"}}
                    for i in range(1, 5)
                ]
                add_members_to_collection(api_client, collection['id'], test_members, dry_run)
                # END TEST SECTION

                # Create a resource from the collection, including ports
                collection_resource = create_resource_from_collection(api_client, collection['id'], clean_dst, rule.get('ports', []), dry_run)
                resources.append(collection_resource)
                
                # Create a new resource group for this collection
                collection_resource_group = {
                    "id": str(uuid.uuid4()),
                    "name": f"{clean_dst}-resource-group",
                    "inherited": [],
                    "resources": [collection_resource['id']]
                }
                logger.info(f"Creating resource group for collection: {json.dumps(collection_resource_group, indent=2)}")
                if not dry_run:
                    created_collection_group = api_client.upsert_resource_group(**collection_resource_group)
                    resource_groups.append(created_collection_group)
                else:
                    resource_groups.append(collection_resource_group)

                # Create policy for this collection
                collection_policy = {
                    "id": str(uuid.uuid4()),
                    "source": {
                        "id": str(uuid.uuid4()),
                        "predicate": {
                            "Or": [
                                {
                                    "id": str(uuid.uuid4()),
                                    "predicate": {"InUserGroup": group['id']}
                                } for group in user_groups
                            ]
                        }
                    },
                    "dest": collection_resource_group['id'],
                    "action": "Accept"
                }
                logger.info(f"Creating policy for collection: {json.dumps(collection_policy, indent=2)}")
                if not dry_run:
                    created_collection_policy = api_client.upsert_policy(**collection_policy)
                    policies.append(created_collection_policy)
                else:
                    policies.append(collection_policy)

            else:
                ports = [parse_port(port) for port in rule.get('ports', [])]
                resource = {
                    "id": str(uuid.uuid4()),
                    "name": clean_dst,
                    "protocol": ports[0][1] if ports else "tcp",
                    "location": {"type": "dns", "value": clean_dst},
                    "ports": {"collection": {"ports": [port[0] for port in ports]}}
                }
                logger.info(f"Creating resource: {json.dumps(resource, indent=2)}")
                if not dry_run:
                    created_resource = api_client.upsert_resource(**resource)
                    resources.append(created_resource)
                    resource_group["resources"].append(created_resource['id'])
                else:
                    resources.append(resource)
                    resource_group["resources"].append(resource['id'])

        if resource_group["resources"]:
            logger.info(f"Creating resource group: {json.dumps(resource_group, indent=2)}")
            if not dry_run:
                created_group = api_client.upsert_resource_group(**resource_group)
                resource_groups.append(created_group)
            else:
                resource_groups.append(resource_group)

            # Create policy for each rule (except for collections, which are handled separately)
            policy = {
                "id": str(uuid.uuid4()),
                "source": {
                    "id": str(uuid.uuid4()),
                    "predicate": {
                        "Or": [
                            {
                                "id": str(uuid.uuid4()),
                                "predicate": {"InUserGroup": group['id']}
                            } for group in user_groups
                        ]
                    }
                },
                "dest": resource_group['id'],
                "action": "Accept"
            }
            logger.info(f"Creating policy: {json.dumps(policy, indent=2)}")
            if not dry_run:
                created_policy = api_client.upsert_policy(**policy)
                policies.append(created_policy)
            else:
                policies.append(policy)

    return user_groups, resources, resource_groups, collections, policies

def export_portable_policies(api_client):
    export_data = {
        "user_groups": [],
        "collections": [],
        "resources": [],
        "resource_groups": [],
        "policies": []
    }

    # Get user groups
    user_groups = api_client.get_groups()
    for group_id, group_data in user_groups.items():
        export_data["user_groups"].append({
            "name": group_data["name"],
            "users": api_client.list_users_in_group(group_id=group_id).get("users", [])
        })

    # Get collections
    collections = api_client.get_collections()
    for collection_id, collection_data in collections.items():
        collection_detail = api_client.get_collection(id=collection_id)
        export_data["collections"].append({
            "name": collection_data["name"],
            "description": collection_data.get("description", ""),
            "members": collection_detail.get("members", [])
        })

    # Get resources, resource groups, and policies
    policy_data = api_client.get_policy()
    
    # Resources
    for resource_id, resource_data in policy_data.get("resources", {}).items():
        export_data["resources"].append({
            "name": resource_data["name"],
            "protocol": resource_data.get("protocol", ""),
            "location": resource_data.get("location", {}),
            "ports": resource_data.get("ports", {})
        })

    # Resource groups
    for group_id, group_data in policy_data.get("resource_groups", {}).items():
        export_data["resource_groups"].append({
            "name": group_data["name"],
            "resources": [policy_data["resources"][res_id]["name"] for res_id in group_data.get("resources", [])]
        })

    # Policies
    for policy_id, policy_data in policy_data.get("policies", {}).items():
        dest_group = policy_data.get("resource_groups", {}).get(policy_data.get("dest", ""), {})
        dest_name = dest_group.get("name", "")
        export_data["policies"].append({
            "source": {
                "predicate": policy_data.get("source", {}).get("predicate", {})
            },
            "dest": dest_name,
            "action": policy_data.get("action", "")
        })

    return export_data

def main():
    parser = argparse.ArgumentParser(description="Translate YAML policy to API calls")
    parser.add_argument("-a", "--address", required=True, help="API base address")
    parser.add_argument("-f", "--file", required=True, help="YAML file path")
    args = parser.parse_args()

    base_url = f"https://{args.address}"
    
    email = input("Enter your email: ")
    password = getpass.getpass("Enter your password: ")

    try:
        session = create_session(base_url, email, password)
        openapi_spec = get_openapi_spec(session, base_url)
        logger.info("OpenAPI spec retrieved successfully.")
    except requests.RequestException as e:
        logger.error(f"Failed to initialize: {e}")
        return

    api_client = DynamicAPIClient(session, base_url, openapi_spec)

    yaml_data = load_yaml_file(args.file)

    # Perform dry run
    user_groups, resources, resource_groups, collections, policies = create_policies(api_client, yaml_data, dry_run=True)

    print("\nDry run complete. Here's what will be created:")
    print(f"\nUser Groups: {json.dumps(user_groups, indent=2)}")
    print(f"\nResources: {json.dumps(resources, indent=2)}")
    print(f"\nResource Groups: {json.dumps(resource_groups, indent=2)}")
    print(f"\nCollections: {json.dumps(collections, indent=2)}")
    print(f"\nPolicies: {json.dumps(policies, indent=2)}")
    
    proceed = input("\nDo you want to proceed with creating these policies? (y/n): ").lower()
    if proceed != 'y':
        print("Operation cancelled.")
        return
    
    # If user confirms, create the policies for real
    user_groups, resources, resource_groups, collections, policies = create_policies(api_client, yaml_data, dry_run=False)

    logger.info("Policies created successfully.")

    export_choice = input("Do you want to export the policies? (y/n): ").lower()
    if export_choice == 'y':
        try:
            export_data = export_portable_policies(api_client)
            
            filename = f"{args.address}-portable-export.json"
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            logger.info(f"Portable policies exported to {filename}")
        except Exception as e:
            logger.error(f"Failed to export policies: {str(e)}")

if __name__ == "__main__":
    main()
