import requests, json

BASE = 'http://localhost:8000/api/v1'

def main():
    login = requests.post(f"{BASE}/auth/login", data={'username':'admin','password':'Admin123!'})
    print('LOGIN', login.status_code)
    if login.status_code != 200:
        print('Login failed:', login.text)
        return
    token = login.json().get('access_token')
    print('TOKEN present:', bool(token))
    headers = {'Authorization': f'Bearer {token}'}
    stats = requests.get(f"{BASE}/security/stats", headers=headers)
    print('STATS', stats.status_code)
    try:
        print(json.dumps(stats.json(), indent=2))
    except Exception as e:
        print('Failed to parse stats JSON:', e)

if __name__ == '__main__':
    main()
