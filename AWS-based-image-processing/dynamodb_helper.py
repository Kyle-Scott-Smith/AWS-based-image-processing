import json
import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
import logging
from datetime import datetime
import uuid
from decimal import Decimal
from secrets_manager_helper import SecretsManagerHelper

# Set up logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class DynamoDBHelper:
    def __init__(self):
        try:
            self.region = 'ap-southeast-2'
            
            # Try to get credentials from Secrets Manager
            secrets_helper = SecretsManagerHelper()
            credentials = secrets_helper.get_database_credentials()
            
            if credentials and credentials.get('access_key_id') and credentials.get('secret_access_key'):
                # Use credentials from Secrets Manager
                self.dynamodb = boto3.resource('dynamodb',
                    aws_access_key_id=credentials['access_key_id'],
                    aws_secret_access_key=credentials['secret_access_key'],
                    region_name=self.region
                )
                logger.info("Using credentials from Secrets Manager for DynamoDB")
            else:
                # Fall back to default credentials (IAM role)
                self.dynamodb = boto3.resource('dynamodb', region_name=self.region)
                logger.info("Using default IAM role credentials for DynamoDB")
            
            self.table_name = 'ImageMetadata'
            self.table = self.dynamodb.Table(self.table_name)
            
            # Create table if it doesn't exist
            self._create_table_if_not_exists()
            
            logger.info("DynamoDB helper initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize DynamoDB helper: {e}")
            raise
    
    def _create_table_if_not_exists(self):
        """Create DynamoDB table if it doesn't exist, handle race conditions safely"""
        try:
            self.table.load()
            logger.info(f"Table {self.table_name} already exists")
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                try:
                    logger.info(f"Creating table {self.table_name}...")

                    table = self.dynamodb.create_table(
                        TableName="ImageMetadata",
                        KeySchema=[
                            {"AttributeName": "ImageID", "KeyType": "HASH"}
                        ],
                        AttributeDefinitions=[
                            {"AttributeName": "ImageID", "AttributeType": "S"},
                            {"AttributeName": "UserID", "AttributeType": "S"}
                        ],
                        BillingMode="PAY_PER_REQUEST",
                        GlobalSecondaryIndexes=[
                            {
                                "IndexName": "UserIndex",
                                "KeySchema": [
                                    {"AttributeName": "UserID", "KeyType": "HASH"}
                                ],
                                "Projection": {"ProjectionType": "ALL"}
                            }
                        ]
                    )

                    table.meta.client.get_waiter('table_exists').wait(TableName=self.table_name)
                    logger.info(f"Table {self.table_name} created successfully")

                    self.table = self.dynamodb.Table(self.table_name)

                except ClientError as create_error:
                    err_code = create_error.response['Error']['Code']
                    if err_code == 'ResourceInUseException':
                        logger.info(f"Table {self.table_name} already being created by another worker")
                        self.table = self.dynamodb.Table(self.table_name)
                    else:
                        logger.error(f"Error creating table {self.table_name}: {create_error}")
                        raise
            else:
                logger.error(f"Error checking table {self.table_name}: {e}")
                raise

    def _convert_floats_to_decimals(self, obj):
        """Recursively convert float values to Decimal for DynamoDB compatibility"""
        if isinstance(obj, float):
            return Decimal(str(obj))
        elif isinstance(obj, dict):
            return {k: self._convert_floats_to_decimals(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_floats_to_decimals(v) for v in obj]
        else:
            return obj

    def put_image_metadata(self, image_id, user_id, metadata):
        try:
            item = {
                "ImageID": str(image_id),
                "UserID": str(user_id),
                "Filename": metadata.get("filename", ""),
                "Filter": metadata.get("filter", ""),
                "Strength": Decimal(str(metadata.get("strength", 0))),
                "SizeMultiplier": Decimal(str(metadata.get("size_multiplier", 1.0))),
                "Format": metadata.get("format", "jpeg"),
                "CreatedAt": datetime.utcnow().isoformat()
            }
            self.table.put_item(Item=item)
            logger.info(f"Successfully stored metadata for {image_id}")
        except Exception as e:
            logger.error(f"Error putting item in DynamoDB: {e}")
            raise

    def get_image_metadata(self, image_id):
        try:
            response = self.table.get_item(Key={'ImageID': str(image_id)})
            item = response.get('Item', None)
            if item:
                logger.info(f"Successfully retrieved metadata for image {image_id}")
            else:
                logger.warning(f"Metadata not found for image {image_id}")
            return item
        except ClientError as e:
            logger.error(f"Error getting item from DynamoDB: {e}")
            return None

    def get_user_images(self, user_id):
        try:
            response = self.table.query(
                IndexName='UserIndex',
                KeyConditionExpression=Key('UserID').eq(str(user_id))
            )
            items = response.get('Items', [])
            logger.info(f"Retrieved {len(items)} images for user {user_id}")
            return items
        except ClientError as e:
            logger.error(f"Error querying DynamoDB: {e}")
            return []

    def delete_image_metadata(self, image_id):
        try:
            self.table.delete_item(Key={'ImageID': str(image_id)})
            logger.info(f"Successfully deleted metadata for image {image_id}")
            return True
        except ClientError as e:
            logger.error(f"Error deleting item from DynamoDB: {e}")
            return False

    def update_image_metadata(self, image_id, update_expression, expression_values):
        try:
            expression_values = self._convert_floats_to_decimals(expression_values)
            
            response = self.table.update_item(
                Key={'ImageID': str(image_id)},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_values,
                ReturnValues="UPDATED_NEW"
            )
            logger.info(f"Successfully updated metadata for image {image_id}")
            return response.get('Attributes', {})
        except ClientError as e:
            logger.error(f"Error updating item in DynamoDB: {e}")
            return None
        
    # Add this method to both S3Helper and DynamoDBHelper classes
    def _get_database_credentials(self):
        """Get database credentials from Secrets Manager"""
        try:
            secrets_client = boto3.client('secretsmanager', region_name=self.region)
            response = secrets_client.get_secret_value(
                SecretId='n11962810-asses2-secret'
            )
            secret_data = json.loads(response['SecretString'])
            return secret_data
        except Exception as e:
            logger.warning(f"Failed to get credentials from Secrets Manager: {e}")
            # Fall back to default credentials
            return None