

# config.py
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    API_KEY = os.getenv('API_KEY', 'your-secure-api-key')
    WG_INTERFACE = os.getenv('WG_INTERFACE', 'wg0')
    WG_CONFIG_PATH = os.getenv('WG_CONFIG_PATH', '/etc/wireguard/wg0.conf')
    IP_RANGE = os.getenv('IP_RANGE', '10.0.0.0/24')  # محدوده IP قابل تخصیص
    SERVER_IP = os.getenv('SERVER_IP', '10.0.0.1')   # IP سرور در شبکه وایرگارد
