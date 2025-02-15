

# utils.py


# app.py
from flask import Flask, request, jsonify
from config import Config
from utils import WireGuardUtils
import subprocess
from functools import wraps

app = Flask(__name__)

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if api_key and api_key == Config.API_KEY:
            return f(*args, **kwargs)
        return jsonify({'error': 'Invalid API key'}), 401
    return decorated

@app.route('/api/peers', methods=['POST'])
@require_api_key
def create_peer():
    """ایجاد peer جدید با IP خودکار"""
    try:
        # پیدا کردن IP آزاد
        new_ip = WireGuardUtils.find_next_available_ip()
        
        # تولید کلیدها
        private_key, public_key, preshared_key = WireGuardUtils.generate_keys()
        
        # به‌روزرسانی فایل کانفیگ
        WireGuardUtils.update_config_file(public_key, preshared_key, new_ip)
        
        # اعمال تغییرات در وایرگارد
        subprocess.run([
            'wg', 'set', Config.WG_INTERFACE,
            'peer', public_key,
            'preshared-key', preshared_key,
            'allowed-ips', f"{new_ip}/32"
        ], check=True)
        
        # ذخیره تغییرات
        subprocess.run(['wg-quick', 'save', Config.WG_INTERFACE], check=True)
        
        # آماده کردن کانفیگ کلاینت
        client_config = f"""[Interface]
PrivateKey = {private_key}
Address = {new_ip}/24
DNS = 8.8.8.8

[Peer]
PublicKey = {subprocess.check_output(['wg', 'show', Config.WG_INTERFACE, 'public-key']).decode().strip()}
PresharedKey = {preshared_key}
AllowedIPs = 0.0.0.0/0
Endpoint = your-server:51820
PersistentKeepalive = 25"""

        return jsonify({
            'public_key': public_key,
            'private_key': private_key,
            'preshared_key': preshared_key,
            'allowed_ip': new_ip,
            'client_config': client_config
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/peers/<public_key>', methods=['DELETE'])
@require_api_key
def delete_peer(public_key):
    """حذف peer"""
    try:
        # حذف از وایرگارد
        subprocess.run([
            'wg', 'set', Config.WG_INTERFACE,
            'peer', public_key,
            'remove'
        ], check=True)
        
        # به‌روزرسانی فایل کانفیگ
        config = WireGuardUtils.read_config_file()
        # حذف بخش مربوط به peer
        sections = re.split(r'\n(?=\[Peer\])', config)
        new_sections = [s for s in sections if f'PublicKey = {public_key}' not in s]
        new_config = '\n'.join(new_sections)
        
        WireGuardUtils.write_config_file(new_config)
        
        # ذخیره تغییرات
        subprocess.run(['wg-quick', 'save', Config.WG_INTERFACE], check=True)
        
        return jsonify({'message': 'Peer removed successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/peers', methods=['GET'])
@require_api_key
def get_peers():
    """دریافت لیست همه peerها با IP هایشان"""
    try:
        # خواندن خروجی wg show
        output = subprocess.check_output(['wg', 'show', Config.WG_INTERFACE, 'dump']).decode()
        
        peers = []
        lines = output.split('\n')
        for line in lines:
            if line:
                parts = line.split('\t')
                if len(parts) >= 3:
                    peers.append({
                        'public_key': parts[1],
                        'preshared_key': parts[2] if parts[2] != '(none)' else None,
                        'allowed_ips': parts[3],
                        'endpoint': parts[4] if len(parts) > 4 and parts[4] != '(none)' else None,
                        'latest_handshake': parts[5] if len(parts) > 5 else None,
                        'transfer_rx': parts[6] if len(parts) > 6 else None,
                        'transfer_tx': parts[7] if len(parts) > 7 else None
                    })
                    
        return jsonify(peers)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
