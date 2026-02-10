# agent.py
import requests
from core import collect_devices

SERVER = "http://localhost:5000/agent"

def send_inventory():
    requests.post(SERVER, json=collect_devices())
