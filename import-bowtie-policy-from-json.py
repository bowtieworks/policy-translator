import argparse
import json
import requests
import logging
import getpass
import uuid

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
                logger.error(f"Request payload: {json.dumps(kwargs, indent=2)}")
                raise e
            return response.json() if response.text else None
        
        return api_call

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

def import_policies(api_client, import_data):
    # Import user groups
    group_id_map = {}
    for group in import_data['user_groups']:
        new_group = api_client.upsert_group(id=str(uuid.uuid4()), name=group['name'])
        group_id_map[group['name']] = new_group['id']
        for user in group['users']:
            api_client.add_users_to_group(group_id=new_group['id'], users=[{"email": user}])

    # Import collections
    collection_id_map = {}
    for collection in import_data['collections']:
        new_collection = api_client.upsert_collection(id=str(uuid.uuid4()), name=collection['name'], description=collection['description'])
        collection_id_map[collection['name']] = new_collection['id']
        members = [{"id": str(uuid.uuid4()), **member} for member in collection['members'].values()]
        api_client.add_members_to_collection(collection_id=new_collection['id'], members=members)

    # Import resources
    resource_id_map = {}
    for resource in import_data['resources']:
        if resource['name'] != "All IPv4":  # Skip "All IPv4" resource
            resource_id = str(uuid.uuid4())
            if resource['location']['type'] == 'collection':
                resource['location']['value'] = collection_id_map.get(resource['name'].split('.')[0], resource['location']['value'])
            new_resource = api_client.upsert_resource(id=resource_id, **resource)
            resource_id_map[resource['name']] = new_resource['id']

    # Import resource groups
    group_id_map = {}
    for group in import_data['resource_groups']:
        if group['name'] != "Allow All":  # Skip "Allow All" resource group
            new_group = api_client.upsert_resource_group(
                id=str(uuid.uuid4()),
                name=group['name'],
                inherited=[],
                resources=[resource_id_map[res_name] for res_name in group['resources'] if res_name != "All IPv4"]
            )
            group_id_map[group['name']] = new_group['id']

    # Import policies
    for policy in import_data['policies']:
        if policy['dest'] != "Allow All":  # Skip policies with "Allow All" destination
            new_policy = {
                "id": str(uuid.uuid4()),
                "source": {
                    "id": str(uuid.uuid4()),
                    "predicate": policy['source']['predicate']
                },
                "dest": group_id_map.get(policy['dest'], str(uuid.uuid4())),
                "action": policy['action']
            }
            api_client.upsert_policy(**new_policy)

    logger.info("All policies and related objects have been imported successfully.")

def main():
    parser = argparse.ArgumentParser(description="Import policies from JSON file")
    parser.add_argument("-a", "--address", required=True, help="API base address")
    parser.add_argument("-f", "--file", required=True, help="JSON import file path")
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

    with open(args.file, 'r') as f:
        import_data = json.load(f)

    try:
        import_policies(api_client, import_data)
    except Exception as e:
        logger.error(f"Failed to import policies: {str(e)}")

if __name__ == "__main__":
    main()
