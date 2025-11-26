import json
import boto3
import io
from botocore.exceptions import NoCredentialsError, ClientError
import logging
import sys
import time
import random
from secrets_manager_helper import SecretsManagerHelper

# Set up logging to output to stdout (Docker captures this)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

class S3Helper:
    def __init__(self):
        try:
            self.region = 'ap-southeast-2'
            logger.info("Initializing S3 helper...")
            self.region = 'ap-southeast-2'
            self.original_bucket = 'n11957948-original-images'
            self.processed_bucket = 'n11957948-processed-images'
            
            # Try to get credentials from Secrets Manager
            secrets_helper = SecretsManagerHelper()
            credentials = secrets_helper.get_database_credentials()
            
            if credentials and credentials.get('access_key_id') and credentials.get('secret_access_key'):
                # Use credentials from Secrets Manager
                self.s3_client = boto3.client('s3',
                    aws_access_key_id=credentials['access_key_id'],
                    aws_secret_access_key=credentials['secret_access_key'],
                    region_name=self.region
                )
                logger.info("Using credentials from Secrets Manager for S3")
            else:
                # Fall back to default credentials (IAM role)
                self.s3_client = boto3.client('s3', region_name=self.region)
                logger.info("Using default IAM role credentials for S3")
            
            # Create buckets if they don't exist
            self._create_bucket_if_not_exists(self.original_bucket)
            self._create_bucket_if_not_exists(self.processed_bucket)
            
            # Tag the buckets
            self._tag_bucket(self.original_bucket)
            self._tag_bucket(self.processed_bucket)
            
            logger.info("S3 helper initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize S3 helper: {e}")
            raise
    
    def _create_bucket_if_not_exists(self, bucket_name):
        """Create S3 bucket if it doesn't exist, handle race conditions safely"""
        try:
            # Check if bucket exists (owned by you or someone else)
            self.s3_client.head_bucket(Bucket=bucket_name)
            logger.info(f"Bucket {bucket_name} already exists")
        except ClientError as e:
            error_code = e.response["Error"]["Code"]

            if error_code in ("404", "NoSuchBucket"):
                try:
                    logger.info(f"Creating bucket {bucket_name}...")
                    self.s3_client.create_bucket(
                        Bucket=bucket_name,
                        CreateBucketConfiguration={'LocationConstraint': 'ap-southeast-2'}
                    )
                    logger.info(f"Bucket {bucket_name} created successfully")
                except self.s3_client.exceptions.BucketAlreadyOwnedByYou:
                    logger.info(f"Bucket {bucket_name} already owned by you (safe to ignore)")
                except self.s3_client.exceptions.BucketAlreadyExists:
                    logger.warning(f"Bucket {bucket_name} already exists globally — using it")
                except ClientError as create_error:
                    if create_error.response["Error"]["Code"] in ("BucketAlreadyOwnedByYou", "OperationAborted"):
                        logger.info(f"Bucket {bucket_name} already created by another worker")
                    else:
                        logger.error(f"Unexpected error creating bucket {bucket_name}: {create_error}")
                        raise
            else:
                logger.error(f"Error checking bucket {bucket_name}: {e}")
                raise

    
    def _tag_bucket(self, bucket_name, max_retries=5):
        """Tag S3 bucket with required tags, with retry/backoff to handle race conditions"""
        qut_username = 'n11957948@qut.edu.au'
        purpose = 'assessment-2'

        for attempt in range(1, max_retries + 1):
            try:
                self.s3_client.put_bucket_tagging(
                    Bucket=bucket_name,
                    Tagging={
                        'TagSet': [
                            {'Key': 'qut-username', 'Value': qut_username},
                            {'Key': 'purpose', 'Value': purpose}
                        ]
                    }
                )
                logger.info(f"Bucket {bucket_name} tagged successfully")
                return
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "OperationAborted" and attempt < max_retries:
                    wait = (2 ** attempt) + random.random()
                    logger.warning(
                        f"Tagging conflict for {bucket_name}, retrying in {wait:.1f}s "
                        f"(attempt {attempt}/{max_retries})"
                    )
                    time.sleep(wait)
                    continue
                else:
                    logger.error(f"Error tagging bucket {bucket_name}: {e}")
                    return
    

    
    def upload_image(self, image_data, image_id, is_processed=False):
        """Upload image to S3"""
        bucket = self.processed_bucket if is_processed else self.original_bucket
        try:
            logger.info(f"Attempting to upload image {image_id} to bucket {bucket}")
            
            response = self.s3_client.put_object(
                Bucket=bucket,
                Key=image_id,
                Body=image_data,
                ContentType='image/jpeg'
            )
            
            logger.info(f"Successfully uploaded image {image_id} to {bucket}")
            logger.debug(f"Upload response: {response}")
            
            # Verify the upload worked
            try:
                self.s3_client.head_object(Bucket=bucket, Key=image_id)
                logger.info(f"Successfully verified upload of {image_id}")
            except Exception as e:
                logger.error(f"Failed to verify upload: {e}")
                
            return True
        except Exception as e:
            logger.error(f"Error uploading to S3: {e}")
            return False
    
    def download_image(self, image_id, is_processed=False):
        """Download image from S3"""
        bucket = self.processed_bucket if is_processed else self.original_bucket
        try:
            logger.info(f"Attempting to download image {image_id} from bucket {bucket}")
            
            response = self.s3_client.get_object(Bucket=bucket, Key=image_id)
            image_data = response['Body'].read()
            
            logger.info(f"Successfully downloaded image {image_id} from {bucket}")
            logger.debug(f"Download response headers: {response['ResponseMetadata']['HTTPHeaders']}")
            
            return image_data
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                logger.warning(f"Image {image_id} not found in {bucket}")
            else:
                logger.error(f"Error downloading from S3: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error downloading from S3: {e}")
            return None
    
    def generate_presigned_url(self, image_id, expiration=3600, is_processed=False):
        """Generate presigned URL for direct access"""
        bucket = self.processed_bucket if is_processed else self.original_bucket
        try:
            logger.info(f"Generating presigned URL for image {image_id} in bucket {bucket}")
            logger.info(f"URL will expire in {expiration} seconds")
            
            # First check if the object exists
            try:
                self.s3_client.head_object(Bucket=bucket, Key=image_id)
                logger.info(f"Image {image_id} exists in bucket {bucket}")
            except ClientError as e:
                logger.error(f"Image {image_id} does not exist in bucket {bucket}: {e}")
                return None
            
            url = self.s3_client.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': bucket,
                    'Key': image_id
                },
                ExpiresIn=expiration
            )
            
            logger.info(f"Successfully generated presigned URL for image {image_id}")
            logger.debug(f"Generated URL: {url}")
            
            # Test the URL
            import requests
            test_response = requests.head(url)
            logger.info(f"URL test response: {test_response.status_code}")
            if test_response.status_code == 200:
                logger.info("URL test successful - URL is accessible")
            else:
                logger.warning(f"URL test failed with status: {test_response.status_code}")
            
            return url
        except Exception as e:
            logger.error(f"Error generating presigned URL: {e}")
            return None
    
    def image_exists(self, image_id, is_processed=False):
        """Check if image exists in S3"""
        bucket = self.processed_bucket if is_processed else self.original_bucket
        try:
            logger.info(f"Checking if image {image_id} exists in bucket {bucket}")
            
            self.s3_client.head_object(Bucket=bucket, Key=image_id)
            logger.info(f"Image {image_id} exists in bucket {bucket}")
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                logger.warning(f"Image {image_id} not found in {bucket}")
                return False
            logger.error(f"Error checking image existence: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error checking image existence: {e}")
            return False
        
    def _get_database_credentials(self):
        """Get database credentials from Secrets Manager"""
        try:
            secrets_client = boto3.client('secretsmanager', region_name=self.region)
            response = secrets_client.get_secret_value(
                SecretId='cab432/database/credentials'
            )
            secret_data = json.loads(response['SecretString'])
            return secret_data
        except Exception as e:
            logger.warning(f"Failed to get credentials from Secrets Manager: {e}")
            # Fall back to default credentials
            return None