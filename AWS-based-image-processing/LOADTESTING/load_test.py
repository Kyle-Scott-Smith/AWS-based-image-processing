import requests
import json
import time
import os
import random
from concurrent.futures import ThreadPoolExecutor

# Configuration
SERVER_URL = "http://13.239.24.103:8080"  # Change to your server URL
USERNAME = "admin1"
PASSWORD = "adminpass"
IMAGE_FOLDER = "test_images"  # Folder containing images to test with
MAX_WORKERS = 2  # Number of concurrent requests
REQUEST_DELAY = 3  # Seconds between request batches
TOTAL_REQUESTS = 0  # Total requests to send (0 for infinite)

# Available filters
FILTERS = ["EMBOSS"]

def get_auth_token():
    """Get JWT token for authentication"""
    try:
        response = requests.post(
            f"{SERVER_URL}/api/auth/login",
            json={"username": USERNAME, "password": PASSWORD}
        )
        if response.status_code == 200:
            return response.json()["access_token"]
        else:
            print(f"Authentication failed: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Authentication error: {e}")
        return None

def get_test_images():
    """Get list of test images from the folder"""
    if not os.path.exists(IMAGE_FOLDER):
        print(f"Image folder '{IMAGE_FOLDER}' not found!")
        return []
    
    images = [f for f in os.listdir(IMAGE_FOLDER) if f.lower().endswith(('.png', '.jpg', '.jpeg', '.webp', '.bmp'))]
    if not images:
        print(f"No images found in '{IMAGE_FOLDER}'!")
        return []
    
    return images

def send_single_request(token, image_path):
    """Send a single image processing request"""
    try:
        # Choose random filter and parameters
        filter_type = random.choice(FILTERS)
        strength = 20
        size_multiplier = 1.0
        
        with open(image_path, 'rb') as f:
            files = {'image': (os.path.basename(image_path), f, 'image/jpeg')}
            data = {
                'filter': filter_type,
                'strength': str(strength),
                'size_multiplier': str(size_multiplier)
            }
            
            headers = {'Authorization': f'Bearer {token}'}
            
            start_time = time.time()
            response = requests.post(
                f"{SERVER_URL}/api/filter-image",
                headers=headers,
                files=files,
                data=data
            )
            end_time = time.time()
            
            response_time = end_time - start_time
            
            if response.status_code == 200:
                return {
                    'success': True,
                    'response_time': response_time,
                    'image_size': os.path.getsize(image_path),
                    'filter': filter_type
                }
            else:
                return {
                    'success': False,
                    'response_time': response_time,
                    'error': f"Status {response.status_code}: {response.text}",
                    'filter': filter_type
                }
                
    except Exception as e:
        return {
            'success': False,
            'response_time': 0,
            'error': str(e),
            'filter': filter_type
        }

def send_batch_request(token, image_paths):
    """Send a batch image processing request"""
    try:
        # Choose random filter and parameters
        filter_type = random.choice(FILTERS)
        strength = 75
        size_multiplier = 1.0
        
        files = []
        for image_path in image_paths:
            files.append(('images', (os.path.basename(image_path), open(image_path, 'rb'), 'image/jpeg')))
        
        data = {
            'filter': filter_type,
            'strength': str(strength),
            'size_multiplier': str(size_multiplier)
        }
        
        headers = {'Authorization': f'Bearer {token}'}
        
        start_time = time.time()
        response = requests.post(
            f"{SERVER_URL}/api/batch-filter-images",
            headers=headers,
            files=files,
            data=data
        )
        end_time = time.time()
        
        response_time = end_time - start_time
        
        # Close all opened files
        for _, (_, file_obj, _) in files:
            file_obj.close()
        
        if response.status_code == 200:
            result = response.json()
            return {
                'success': True,
                'response_time': response_time,
                'processed_count': result['processed_count'],
                'error_count': result['error_count'],
                'filter': filter_type
            }
        else:
            return {
                'success': False,
                'response_time': response_time,
                'error': f"Status {response.status_code}: {response.text}",
                'filter': filter_type
            }
            
    except Exception as e:
        return {
            'success': False,
            'response_time': 0,
            'error': str(e),
            'filter': filter_type
        }

def run_load_test():
    """Main function to run the load test"""
    print("Starting load test...")
    print(f"Server: {SERVER_URL}")
    print(f"User: {USERNAME}")
    print(f"Max workers: {MAX_WORKERS}")
    print(f"Request delay: {REQUEST_DELAY}s")
    
    # Get authentication token
    token = get_auth_token()
    if not token:
        return
    
    # Get test images
    image_files = get_test_images()
    if not image_files:
        return
    
    image_paths = [os.path.join(IMAGE_FOLDER, img) for img in image_files]
    print(f"Found {len(image_paths)} test images")
    
    # Statistics
    request_count = 0
    success_count = 0
    total_response_time = 0
    min_response_time = float('inf')
    max_response_time = 0
    
    # Test modes
    use_batch = False # Set to False to test single image endpoints
    
    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            while TOTAL_REQUESTS == 0 or request_count < TOTAL_REQUESTS:
                futures = []
                
                # Submit requests
                for _ in range(MAX_WORKERS):
                    if use_batch:
                        # Use batch endpoint
                        batch_size = random.randint(2, min(5, len(image_paths)))
                        selected_images = random.sample(image_paths, batch_size)
                        futures.append(executor.submit(send_batch_request, token, selected_images))
                    else:
                        # Use single image endpoint
                        selected_image = random.choice(image_paths)
                        futures.append(executor.submit(send_single_request, token, selected_image))
                
                # Wait for results
                for future in futures:
                    result = future.result()
                    request_count += 1
                    
                    if result['success']:
                        success_count += 1
                        response_time = result['response_time']
                        total_response_time += response_time
                        min_response_time = min(min_response_time, response_time)
                        max_response_time = max(max_response_time, response_time)
                        
                        if 'processed_count' in result:  # Batch request
                            print(f"✓ Batch processed {result['processed_count']} images with {result['filter']} in {response_time:.2f}s")
                        else:  # Single request
                            print(f"✓ Processed image with {result['filter']} in {response_time:.2f}s")
                    else:
                        print(f"✗ Failed: {result['error']}")
                
                # Print statistics
                if success_count > 0:
                    avg_response_time = total_response_time / success_count
                    success_rate = (success_count / request_count) * 100
                    
                    print(f"\n--- Statistics ---")
                    print(f"Requests: {request_count}, Success: {success_count} ({success_rate:.1f}%)")
                    print(f"Response time: Min {min_response_time:.2f}s, Avg {avg_response_time:.2f}s, Max {max_response_time:.2f}s")
                    print("-----------------\n")
                
                # Delay before next batch
                time.sleep(REQUEST_DELAY)
                
    except KeyboardInterrupt:
        print("\nLoad test interrupted by user")
    
    # Final statistics
    if success_count > 0:
        avg_response_time = total_response_time / success_count
        success_rate = (success_count / request_count) * 100
        
        print(f"\n=== Final Statistics ===")
        print(f"Total requests: {request_count}")
        print(f"Successful requests: {success_count} ({success_rate:.1f}%)")
        print(f"Min response time: {min_response_time:.2f}s")
        print(f"Avg response time: {avg_response_time:.2f}s")
        print(f"Max response time: {max_response_time:.2f}s")
        print("=======================")

if __name__ == "__main__":
    run_load_test()