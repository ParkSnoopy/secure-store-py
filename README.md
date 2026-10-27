# Secure Store for Python

Example `.env`:  

```dotenv
API_KEY='example-api-key'
API_URL='https://api.example.com'
```

```python
from secure_store import Store

vault = Store.open(".env")
api_key = vault.get("API_KEY")
api_url = vault.get("API_URL")

client = APIClient(api_url, api_key)
```

[Setup, technical details, and security limits](docs/LLM_WIKI.md)  
