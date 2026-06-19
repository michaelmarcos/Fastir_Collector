"""Put the backend dir on sys.path so tests can `import collector`, `app`, etc."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
