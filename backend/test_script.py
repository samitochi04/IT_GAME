import requests
import json

def test_api():
    # Test status endpoint
    print("Testing API Status...")
    status_response = requests.get('http://localhost:5000/api/status')
    print("Status Response:")
    print(json.dumps(status_response.json(), indent=2))

    # Test analysis endpoint
    print("\nTesting PCAP Analysis...")
    analysis_response = requests.get('http://localhost:5000/api/analyze/latest')
    print("Analysis Response:")
    print(json.dumps(analysis_response.json(), indent=2))

if __name__ == "__main__":
    test_api()
