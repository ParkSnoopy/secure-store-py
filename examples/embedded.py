"""Read the vault encrypted inside the Python application build."""

from secure_store import Store

store = Store.embedded()
if not store.get("API_KEY"):
    raise RuntimeError("The demo API key is empty.")
print("Native embedded vault unlocked.")
