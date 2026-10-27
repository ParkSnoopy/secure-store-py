# Secure Store for Python

```python
from secure_store import Store

vault = Store.open("secrets.vault", password)  # Or: Store.embedded()
api_key = vault.get("API_KEY")
```

[Setup, technical details, and security limits](docs/LLM_WIKI.md)  
