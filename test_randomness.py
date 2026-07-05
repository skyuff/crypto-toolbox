import requests
import random

random.seed(0)
bytes_data = bytes(random.randint(0, 255) for _ in range(1250))
hex_str = bytes_data.hex()

r = requests.post(
    'http://localhost:8080/api/randomness/test',
    json={'input': hex_str, 'format': 'hex', 'selectedMethods': list(range(1, 29))},
    timeout=120
)
print('status:', r.status_code)
data = r.json()['data']
print('bitLength:', data['bitLength'])
print('overallPass:', data['overallPass'])
for t in data['tests']:
    print(f"[{t['id']}] {t['name']}: p={t['pValue']:.6f}, pass={t['pass']}")
