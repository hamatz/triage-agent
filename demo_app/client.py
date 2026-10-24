import requests

def fetch_user_profile(user_id):
    # Standard request, no stream or raw chunked deflate used
    resp = requests.get(f"https://api.internal/users/{user_id}")
    return resp.json()
