import requests
import json
import sys
import time

def test_api(max_retries=3):
    base_url = 'http://localhost:5000'
    
    print("Checking if server is running...")
    
    # Try to connect to the server
    for attempt in range(max_retries):
        try:
            # Test status endpoint
            print(f"\nAttempt {attempt + 1}: Testing API Status...")
            status_response = requests.get(f'{base_url}/api/status')
            
            if status_response.status_code == 200:
                print("Status Response:")
                print(json.dumps(status_response.json(), indent=2))

                # Test analysis endpoint
                print("\nTesting PCAP Analysis...")
                analysis_response = requests.get(f'{base_url}/api/analyze/latest')
                print("Analysis Response:")
                print(json.dumps(analysis_response.json(), indent=2))
                return
            else:
                print(f"Error: Server returned status code {status_response.status_code}")
                
        except requests.exceptions.ConnectionError:
            print(f"Connection failed. Make sure the Flask server is running on {base_url}")
            if attempt < max_retries - 1:
                print("Retrying in 2 seconds...")
                time.sleep(2)
        except json.JSONDecodeError:
            print("Error: Received invalid JSON response from server")
            print(f"Raw response: {status_response.text}")
        except Exception as e:
            print(f"Unexpected error: {str(e)}")
    
    print("\nFailed to connect after multiple attempts.")
    print("Please ensure:")
    print("1. The Flask server is running (python main.py)")
    print("2. The server is accessible at http://localhost:5000")
    print("3. No firewall is blocking the connection")
    sys.exit(1)

if __name__ == "__main__":
    test_api()
