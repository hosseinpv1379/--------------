import ipaddress
import re
import subprocess
import os
from config import Config

class WireGuardUtils:
    @staticmethod
    def read_config_file():
        """خواندن فایل کانفیگ وایرگارد"""
        try:
            with open(Config.WG_CONFIG_PATH, 'r') as f:
                return f.read()
        except FileNotFoundError:
            return ""

    @staticmethod
    def write_config_file(content):
        """نوشتن در فایل کانفیگ وایرگارد"""
        with open(Config.WG_CONFIG_PATH, 'w') as f:
            f.write(content)

    @staticmethod
    def get_used_ips():
        """استخراج IP های استفاده شده از فایل کانفیگ"""
        config = WireGuardUtils.read_config_file()
        used_ips = set()
        
        # افزودن IP سرور
        used_ips.add(ipaddress.ip_address(Config.SERVER_IP))
        
        # پیدا کردن همه IP های تخصیص داده شده
        ip_pattern = r'AllowedIPs\s*=\s*([0-9./,\s]+)'
        matches = re.finditer(ip_pattern, config)
        
        for match in matches:
            ips = match.group(1).split(',')
            for ip in ips:
                ip = ip.strip()
                if '/' in ip:
                    ip = ip.split('/')[0]
                used_ips.add(ipaddress.ip_address(ip))
                
        return used_ips

    @staticmethod
    def find_next_available_ip():
        """پیدا کردن اولین IP آزاد"""
        used_ips = WireGuardUtils.get_used_ips()
        network = ipaddress.ip_network(Config.IP_RANGE)
        
        for ip in network.hosts():
            if ip not in used_ips:
                return str(ip)
        
        raise Exception("No available IP addresses")

    @staticmethod
    def generate_keys():
        """تولید کلیدهای وایرگارد"""
        private_key = subprocess.check_output(['wg', 'genkey']).decode().strip()
        public_key = subprocess.check_output(['wg', 'pubkey'], 
                                          input=private_key.encode()).decode().strip()
        preshared_key = subprocess.check_output(['wg', 'genpsk']).decode().strip()
        return private_key, public_key, preshared_key

    @staticmethod
    def update_config_file(public_key, preshared_key, allowed_ips):
        """به‌روزرسانی فایل کانفیگ"""
        config = WireGuardUtils.read_config_file()
        
        # ایجاد بخش پیر جدید
        peer_config = f"""
[Peer]
PublicKey = {public_key}
PresharedKey = {preshared_key}
AllowedIPs = {allowed_ips}/32
"""
        
        # اضافه کردن به انتهای فایل
        if not config.endswith('\n'):
            config += '\n'
        config += peer_config
        
        WireGuardUtils.write_config_file(config)
