# secrets_manager_helper.py
import boto3
import json
import logging
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

class SecretsManagerHelper:
    def __init__(self):
        self.region = 'ap-southeast-2'
        self.secrets_client = boto3.client('secretsmanager', region_name=self.region)
    
    def get_database_credentials(self):
        """Get database credentials from Secrets Manager"""
        try:
            response = self.secrets_client.get_secret_value(
                SecretId='n11962810-asses2-secret'
            )
            credentials = json.loads(response['SecretString'])
            logger.info("Successfully retrieved credentials from Secrets Manager")
            return credentials
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                logger.warning("Secrets Manager secret not found, using default credentials")
            else:
                logger.error(f"Error retrieving secrets: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error retrieving secrets: {e}")
            return None