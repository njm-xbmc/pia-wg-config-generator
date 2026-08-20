from flask import Flask, render_template, request, send_file, jsonify
import tempfile
import os
import logging
import requests
import urllib3
import zipfile
from piawg import piawg
from datetime import datetime

urllib3.disable_warnings()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

def sanitize_region_for_filename(region_name):
    name = region_name.lower()
    name = name.replace(' ', '-')
    name = ''.join(c if c.isalnum() or c == '-' else '' for c in name)
    name = '-'.join(filter(None, name.split('-')))
    return name

def get_openvpn_config(region_name, protocol, server_list):
    """Generate OpenVPN config for a given region and protocol (udp/tcp)"""
    proto_key = 'ovpntcp' if protocol == 'tcp' else 'ovpnudp'
    port = 502 if protocol == 'tcp' else 1198

    servers = server_list.get(region_name, {}).get('servers', {}).get(proto_key, [])
    if not servers:
        return None, "No servers available for this region/protocol"

    server_ip = servers[0]['ip']
    server_cn = servers[0]['cn']

    config = f"""client
dev tun
proto {protocol}
remote {server_ip} {port}
resolv-retry infinite
nobind
persist-key
persist-tun
cipher aes-128-cbc
auth sha1
tls-client
remote-cert-tls server
verb 1
reneg-sec 0
auth-user-pass
script-security 2
# Server: {server_cn}
# Region: {region_name}
<ca>
-----BEGIN CERTIFICATE-----
MIIHqzCCBZOgAwIBAgIJAJ0u+vd0KcFMMA0GCSqGSIb3DQEBDQUAMIHoMQswCQYD
VQQGEwJVUzELMAkGA1UECBMCQ0ExEzARBgNVBAcTClNhbkpvc2UxEzARBgNVBAoT
ClByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMRswGQYDVQQLExJQcml2YXRlIEludGVy
bmV0IEFjY2VzczETMBEGA1UEAxMKUHJpdmF0ZSBDQTEPMA0GA1UEKRMGc2VydmVy
MScwJQYJKoZIhvcNAQkBFhhzdXBwb3J0QHByaXZhdGVpbnRlcm5ldC5pMB4XDTEy
MDYxNTAzMDgxNFoXDTMyMDYxMDAzMDgxNFowgegxCzAJBgNVBAYTAlVTMQswCQYD
VQQIEwJDQTETMBEGA1UEBxMKU2FuSm9zZTETMBEGA1UEChMKUHJpdmF0ZSBJbnRl
cm5ldCBBY2Nlc3MxGzAZBgNVBAsTElByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMRMw
EQYDVQQDEwpQcml2YXRlIENBMQ8wDQYDVQQpEwZzZXJ2ZXIxJzAlBgkqhkiG9w0B
CQEWGHNpdXBwb3J0QHByaXZhdGVpbnRlcm5ldC5pMIICIjANBgkqhkiG9w0BAQEF
AAOCAg8AMIICCgKCAgEA5QZ7RYlX5JcFbMvDe7GdyaVNBgZdYEiaDDvSdUt/Ob0d
cE4u0OHYuSgkSSEfzJKH7BF62uJE+K96YEJL6/Jvy3YmM6aJHFaHMIVCKEZRVeL
RiOoE0e+L69X/RViJp2OkV3X7RVFiR7R1PNfnzFRDpOVFD9YM36ik5sPOjXRdIg
s7s0bIXQ2D0VhECOc5wPSNpbpIVHi3q2Wbq/e9M/6p3XaEpf0rlnmwcPMqZkTPX
eRzGDtVeSK7C5/f06nFb0+h1J2g0q+k5MLG/K+bHNt8JkO1tUfCGcD9o5aRgPQMj
ZJH7pOKH3bwqB1jj4RRXKzfnGkWmSOUTNWFmECEdTHgkXbFr5HOzMY2JN96RKAM
WJXiAiO/FPvFqJf59FrHqEUWe7TzHLzd22rSxFD1M0X9vX4MrVSXNOqbkjIkQNy
9oAKWTOqjcE8yP/j7ANTxu4OiA3IlR9R+GY3M/+7VkCnB/oE6/kfIhCqo5qk0rq
XYFcGqRCWN0aRXO5wBlN+rH/eFqWKA+IpEnb7v8M7YWJbJN8P5dlY/KGtl0I5mXS
dXbVH5RGqXwWXRPRZTGVMhDNGUv/MBa0U0QFZX+gBDV5I/d3QJRwMhJrVwXhsKU
E5y3t/H0PZqXpb2FKSK9x3A+x4MWy/b5SWX8vBOz/r5nL/y8D5MCAwEAAaNjMGEw
HQYDVR0OBBYEFLKiFlbJrGFN+3l2H5W/bvSXMOMTMB8GA1UdIwQYMBaAFLKiFlbJ
rGFN+3l2H5W/bvSXMOMTMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGG
MA0GCSqGSIb3DQEBDQUAA4ICAQABJmVMRGcbAExjFWFt0GX7c4dXMMsXBKHWQq/j
pnrMPHrGrgGHZp0TQJwH18B8/xTPQjv3i0eBmRMlpZP8GhWwuqPFiZ78EWU5f2Rv
3Ou4K5/tA1qGLwCuiK68Xdwr3a5GkBRqyL4rCdnMYYKaHOO1RDVY7e/lJa9JxnRi
zd1OJCnJr1SfIHV3feTT2WPdq9RYJJzYqxRSxd7+7Y4q3lE7C3qAbNMNhFY6J18x
FbDMh0GH5jE1AkwBt9Ot+j5q+W+dO5bwA3VzNJBJ4ZP9Fa2B1pxbmyp5SFQ2kfp
ZCZ9Y4HPMO7mT8i3EMHL+Io/jvKJ6T9RN6T9SfE7fZkI/b4YCVX7NiGM4PBjl0C
T7M2Zs+8A/5+R4dGx5/Uu3YnEE4IVP/LTrj4UYPpHvmX4oI6xEnhNSIr/bXR2Wl
b7HOiLK/Kc/NbNjzg7T6TtWPM6LY6GVMhBPu9n4j0O/pSIMPlJHiQ8eCi8H4PzY
nfJ8A6xIgLmBpaTaSJ7T6ZKF6V0jBQPGlIJoLFU1HtAmLm7LSTi7JhqC5v2GJXJJ
JwV3i5s2y3g7gMPVzxGQjAFnE+UkU7A/bqzwkFfMYiB/+K+EzTT2I7jFlXGH8Lzn
TqOSwO1TZFV4c5eKWJl7oIrjd9gqK+Ii4Y94i9bFv8OVsONO6Q==
-----END CERTIFICATE-----
</ca>
"""
    return config, None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/regions')
def get_regions():
    """Get available PIA regions for dropdown"""
    try:
        pia = piawg()
        regions = list(pia.server_list.keys())
        regions.sort()
        logger.info(f"Retrieved {len(regions)} available regions")
        return jsonify(regions)
    except Exception as e:
        logger.error(f"Failed to retrieve regions: {str(e)})")
        return jsonify({'error': str(e)}), 500

@app.route('/generate', methods=['POST'])
def generate_config():
    """Generate and download WireGuard config"""
    temp_file = None
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        region = request.form.get('region')
        config_type = request.form.get('config_type', 'wireguard')

        if not all([username, password, region]):
            logger.warning("Config generation attempted with missing fields")
            return jsonify({'error': 'All fields are required'}), 400

        sanitized_region = sanitize_region_for_filename(region)

        if config_type in ('openvpn_udp', 'openvpn_tcp'):
            protocol = 'tcp' if config_type == 'openvpn_tcp' else 'udp'
            pia = piawg()

            if region not in pia.server_list:
                return jsonify({'error': f'Invalid region selected: {region}'}), 400

            logger.info(f"Generating OpenVPN {protocol.upper()} config for region: {region}")

            config_content, error = get_openvpn_config(region, protocol, pia.server_list)
            if error:
                return jsonify({'error': error}), 500

            # Add credentials
            config_content += f"\n<auth-user-pass>\n{username}\n{password}\n</auth-user-pass>\n"

            tunnel_name = f'PIA-{sanitized_region}-{protocol.upper()}'
            filename = f'{tunnel_name}.ovpn'

            with tempfile.NamedTemporaryFile(mode='w', suffix='.ovpn', delete=False) as f:
                f.write(config_content)
                temp_file = f.name

            logger.info(f"OpenVPN config generated successfully for region: {region}")

            response = send_file(temp_file,
                               as_attachment=True,
                               download_name=filename,
                               mimetype='text/plain')

            @response.call_on_close
            def cleanup():
                try:
                    if temp_file and os.path.exists(temp_file):
                        os.unlink(temp_file)
                except Exception as e:
                    logger.error(f"Failed to cleanup temp file: {e}")

            return response

        # WireGuard config
        pia = piawg()

        if region not in pia.server_list:
            logger.warning(f"Invalid region selected: {region}")
            return jsonify({'error': f'Invalid region selected: {region}'}), 400

        logger.info(f"Generating WireGuard config for region: {region}")

        pia.generate_keys()
        pia.set_region(region)

        if not pia.get_token(username, password):
            logger.warning(f"Authentication failed for user: {username}")
            return jsonify({'error': 'Invalid credentials or authentication failed'}), 401

        status, response = pia.addkey()
        if not status:
            logger.error(f"Failed to register key with server for region: {region}")
            return jsonify({'error': 'Failed to register key with server'}), 500

        tunnel_name = f'PIA-{sanitized_region}'

        config_content = f"""[Interface]
Address = {pia.connection['peer_ip']}
PrivateKey = {pia.privatekey}
DNS = {pia.connection['dns_servers'][0]},{pia.connection['dns_servers'][1]}

# Uncomment the below two PostUp and PreDown routing rules if routing containers through WireGuard container
# PostUp = iptables -t nat -A POSTROUTING -o wg+ -j MASQUERADE
# PreDown = iptables -t nat -D POSTROUTING -o wg+ -j MASQUERADE

# Unraid note: leave the next line commented. Used only for naming the tunnel in Unraid
# {tunnel_name}

[Peer]
PublicKey = {pia.connection['server_key']}
Endpoint = {pia.connection['server_ip']}:1337
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write(config_content)
            temp_file = f.name

        logger.info(f"WireGuard config generated successfully for region: {region}")

        filename = f'{tunnel_name}.conf'

        response = send_file(temp_file,
                           as_attachment=True,
                           download_name=filename,
                           mimetype='text/plain')

        @response.call_on_close
        def cleanup():
            try:
                if temp_file and os.path.exists(temp_file):
                    os.unlink(temp_file)
                    logger.debug(f"Cleaned up temp file: {temp_file}")
            except Exception as e:
                logger.error(f"Failed to cleanup temp file {temp_file}: {str(e)}")

        return response

    except Exception as e:
        logger.error(f"Error generating config: {str(e)}")
        if temp_file and os.path.exists(temp_file):
            try:
                os.unlink(temp_file)
            except Exception:
                pass
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
