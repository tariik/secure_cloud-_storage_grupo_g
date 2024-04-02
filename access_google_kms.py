import os
import time
from dotenv import load_dotenv
from google.cloud import kms


def get_key_rings(project_id, location_id):
    # Create the client.
    print("Setting up client...")
    client = kms.KeyManagementServiceClient()
    print("Successfully created client")

    # Call the API.
    location_name = build_location_name(project_id, location_id)
    key_rings = client.list_key_rings(request={'parent': location_name})
    print("key_rings: ", key_rings)
    # Example of iterating over key rings.
    for key_ring in key_rings:
        print(key_ring.name)
        print(key_ring)
    return key_rings


def create_key_ring(project_id, location_id, key_ring_id):
    """
    Creates a new key ring in Cloud KMS
    Args:
        project_id (string): Google Cloud project ID (e.g. 'my-project').
        location_id (string): Cloud KMS location (e.g. 'us-east1').
        key_ring_id (string): ID of the key ring to create (e.g. 'my-key-ring').
    Returns:
        KeyRing: Cloud KMS key ring.
    """
    # Create the client.
    client = kms.KeyManagementServiceClient()
    location_name = build_location_name(project_id, location_id)
    # Build the key ring.
    key_ring = {}
    # Call the API.
    created_key_ring = client.create_key_ring(
        request={'parent': location_name, 'key_ring_id': key_ring_id, 'key_ring': key_ring})
    print('Created key ring: {}'.format(created_key_ring.name))
    return created_key_ring


def create_key_symmetric_encrypt_decrypt(project_id, location_id, key_ring_id, key_id):
    """
    Creates a new symmetric encryption/decryption key in Cloud KMS.
    Args:
        project_id (string): Google Cloud project ID (e.g. 'my-project').
        location_id (string): Cloud KMS location (e.g. 'us-east1').
        key_ring_id (string): ID of the Cloud KMS key ring (e.g. 'my-key-ring').
        key_id (string): ID of the key to create (e.g. 'my-symmetric-key').
    Returns:
        CryptoKey: Cloud KMS key.
    """
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


def create_key_rotation_schedule(project_id, location_id, key_ring_id, key_id):
    """
    Creates a new key in Cloud KMS that automatically rotates.
    Args:
        project_id (string): Google Cloud project ID (e.g. 'my-project').
        location_id (string): Cloud KMS location (e.g. 'us-east1').
        key_ring_id (string): ID of the Cloud KMS key ring (e.g. 'my-key-ring').
        key_id (string): ID of the key to create (e.g. 'my-rotating-key').
    Returns:
        CryptoKey: Cloud KMS key.
    """
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
        },
        # Rotate the key every 30 days.
        'rotation_period': {
            'seconds': 60 * 60 * 24 * 30
        },
        # Start the first rotation in 24 hours.
        'next_rotation_time': {
            'seconds': int(time.time()) + 60 * 60 * 24
        }
    }
    # Call the API.
    created_key = client.create_crypto_key(
        request={'parent': key_ring_name, 'crypto_key_id': key_id, 'crypto_key': key})
    print('Created labeled key: {}'.format(created_key.name))
    return created_key


def build_location_name(project_id, location_id):
    '''Build the parent location name.'''
    return f'projects/{project_id}/locations/{location_id}'


def main():
    load_dotenv()
    project_id = os.getenv('PROJECT_ID')
    location_id = os.getenv('LOCATION_ID')
    # create_key_ring(project_id, location_id, 'my-key-ring')
    get_key_rings(project_id, location_id)


if __name__ == '__main__':
    main()
