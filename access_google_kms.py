import os
import time
from dotenv import load_dotenv
from google.cloud import kms


'''
!!! Ressources on how to use the KMS API !!!
- Installation and basic access
    https://cloud.google.com/kms/docs/reference/libraries#client-libraries-install-python
- Key creation (including key rotation)
    https://cloud.google.com/kms/docs/create-key
- Usage of symmetric keys
    https://cloud.google.com/kms/docs/encrypt-decrypt
- Usage of asymmetric keys
    https://cloud.google.com/kms/docs/encrypt-decrypt-rsa    
'''

def get_key_rings():
    project_id, location_id = get_project_and_location_id()
    # Create the client.
    print("Setting up client...")
    client = kms.KeyManagementServiceClient()
    print("Successfully created client")

    # Call the API.
    location_name = build_location_name()
    key_rings = client.list_key_rings(request={'parent': location_name})
    print("key_rings:")
    for key_ring in key_rings:
        print(key_ring.name)
        print(key_ring)
    return key_rings

def create_key_ring(key_ring_id):
    """
    Creates a new key ring in Cloud KMS
    Args:
        key_ring_id (string): ID of the key ring to create (e.g. 'my-key-ring').
    Returns:
        KeyRing: Cloud KMS key ring.
    """
    # Create the client.
    client = kms.KeyManagementServiceClient()
    location_name = build_location_name()
    # Build the key ring.
    key_ring = {}
    # Call the API.
    created_key_ring = client.create_key_ring(
        request={'parent': location_name, 'key_ring_id': key_ring_id, 'key_ring': key_ring})
    print('Created key ring: {}'.format(created_key_ring.name))
    return created_key_ring

def create_symmetric_key(key_ring_id, key_id):
    """
    Creates a new symmetric encryption/decryption key in Cloud KMS.
    Args:
        key_ring_id (string): ID of the Cloud KMS key ring (e.g. 'my-key-ring').
        key_id (string): ID of the key to create (e.g. 'my-symmetric-key').
    Returns:
        CryptoKey: Cloud KMS key.
    """
    project_id, location_id = get_project_and_location_id()
    client = kms.KeyManagementServiceClient()
    # Build the parent key ring name.
    key_ring_name = client.key_ring_path(project_id, location_id, key_ring_id)
    # Build the key.
    purpose = kms.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT
    algorithm = kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
    key = {
        'purpose': purpose,
        'version_template': {
            'algorithm': algorithm,
        }
    }
    # Call the API.
    created_key = client.create_crypto_key(
        request={'parent': key_ring_name, 'crypto_key_id': key_id, 'crypto_key': key})
    print('Created symmetric key: {}'.format(created_key.name))
    return created_key

def build_location_name():
    '''Build the parent location name.'''
    project_id, location_id = get_project_and_location_id()
    return f'projects/{project_id}/locations/{location_id}'

def get_project_and_location_id():
    project_id = os.getenv('PROJECT_ID')
    location_id = os.getenv('LOCATION_ID')
    return project_id, location_id

def main():
    load_dotenv()
    # create_key_ring('cse-key-ring')
    get_key_rings()


if __name__ == '__main__':
    main()
