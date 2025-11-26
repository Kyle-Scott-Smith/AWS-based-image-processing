import requests
import json
import os
import time
import boto3
from botocore.exceptions import ClientError

def test_s3_dynamodb_integration():
    print("Testing S3 and DynamoDB Integration")
    print("=" * 50)
    
    # Test authentication
    print("1. Testing authentication...")
    try:
        login_data = {"username": "admin1", "password": "adminpass"}
        response = requests.post("http://localhost:8080/api/auth/login", json=login_data)
        token = response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        print("✓ Authentication successful")
    except Exception as e:
        print(f"✗ Authentication failed: {e}")
        return False
    
    # Test image upload and processing
    print("2. Testing image upload and processing...")
    try:
        with open("test_image.jpg", "rb") as f:
            files = {"image": f}
            data = {
                "filter": "EMBOSS",
                "strength": "20",
                "size_multiplier": "1.0"
            }
            response = requests.post(
                "http://localhost:8080/api/filter-image",
                headers=headers,
                files=files,
                data=data
            )
        
        if response.status_code == 200:
            result = response.json()
            image_id = result["image_id"]
            print("✓ Image upload and processing successful")
            print(f"  Image ID: {image_id}")
        else:
            print(f"✗ Image processing failed: {response.text}")
            return False
    except Exception as e:
        print(f"✗ Image processing test failed: {e}")
        return False
    
    # Test listing images
    print("3. Testing image listing...")
    try:
        response = requests.get("http://localhost:8080/api/my-images", headers=headers)
        if response.status_code == 200:
            images = response.json()
            print(f"✓ Retrieved {len(images)} images")
            if len(images) > 0:
                print(f"  First image URL: {images[0]['image_url'][:50]}...")
        else:
            print(f"✗ Image listing failed: {response.text}")
            return False
    except Exception as e:
        print(f"✗ Image listing test failed: {e}")
        return False
    
    # Test download
    print("4. Testing image download...")
    try:
        response = requests.get(f"http://localhost:8080/api/download-image/{image_id}?token={token}")
        if response.status_code == 200:
            # Save downloaded image
            with open("downloaded_test_image.jpg", "wb") as f:
                f.write(response.content)
            print("✓ Image download successful")
            print(f"  Downloaded size: {os.path.getsize('downloaded_test_image.jpg')} bytes")
        else:
            print(f"✗ Image download failed: {response.text}")
            return False
    except Exception as e:
        print(f"✗ Image download test failed: {e}")
        return False
    
    # Test direct S3 access
    print("5. Testing S3 access...")
    try:
        s3 = boto3.client('s3')
        # Check if original image exists in S3
        original_key = f"original_{image_id}"
        response = s3.head_object(Bucket='n11957948-original-images', Key=original_key)
        print("✓ Original image found in S3")
        
        # Check if processed image exists in S3
        response = s3.head_object(Bucket='n11957948-processed-images', Key=image_id)
        print("✓ Processed image found in S3")
    except ClientError as e:
        print(f"✗ S3 access test failed: {e}")
        return False
    
    # Test DynamoDB access
    print("6. Testing DynamoDB access...")
    try:
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table('ImageMetadata')
        response = table.get_item(Key={'image_id': image_id})
        if 'Item' in response:
            item = response['Item']
            print("✓ Image metadata found in DynamoDB")
            print(f"  Filter: {item['filter']}, User: {item['user_id']}")
        else:
            print("✗ Image metadata not found in DynamoDB")
            return False
    except ClientError as e:
        print(f"✗ DynamoDB access test failed: {e}")
        return False
    
    # Test statelessness by restarting app and checking data persistence
    print("7. Testing statelessness...")
    print("   Please restart the application and press Enter to continue")
    input()
    
    try:
        # Test that we can still access the image after restart
        response = requests.get("http://localhost:8080/api/my-images", headers=headers)
        if response.status_code == 200 and len(response.json()) > 0:
            print("✓ Data persistence confirmed after restart")
        else:
            print("✗ Data lost after restart")
            return False
    except Exception as e:
        print(f"✗ Statelessness test failed: {e}")
        return False
    
    print("=" * 50)
    print("All tests passed! S3 and DynamoDB integration is working correctly.")
    return True

if __name__ == "__main__":
    # Create a test image if it doesn't exist
    if not os.path.exists("test_image.jpg"):
        from PIL import Image
        img = Image.new('RGB', (100, 100), color='red')
        img.save("test_image.jpg")
        print("Created test_image.jpg for testing")
    
    test_s3_dynamodb_integration()