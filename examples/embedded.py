"""Run after building a native module with examples/demo.env embedded."""

from secure_store import Store

store = Store.embedded()
if not store.get("API_KEY"):
    raise RuntimeError("The demo API key is empty.")
print("Native embedded vault unlocked.")
