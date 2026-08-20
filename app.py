from flask import Flask, render_template, request, send_file, jsonify
import tempfile
import os
import logging
import urllib3
from piawg import piawg
from protonvpn import generate_config as generate_proton_config, get_server_list as proton_server_list

urllib3.disable_warnings()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

PROTON_CA = """-----BEGIN CERTIFICATE-----
MIIFnTCCA4WgAwIBAgIUCI574SM3Lyh47GyNl0WAOYrqb5QwDQYJKoZIhvcNAQEL
BQAwXjELMAkGA1UEBhMCQ0gxHzAdBgNVBAoMFlByb3RvbiBUZWNobm9sb2dpZXMg
QUcxEjAQBgNVBAsMCVByb3RvblZQTjEaMBgGA1UEAwwRUHJvdG9uVlBOIFJvb3Qg
Q0EwHhcNMTkxMDE3MDgwNjQxWhcNMzkxMDEyMDgwNjQxWjBeMQswCQYDVQQGEwJD
SDEfMB0GA1UECgwWUHJvdG9uIFRlY2hub2xvZ2llcyBBRzESMBAGA1UECwwJUHJv
dG9uVlBOMRowGAYDVQQDDBFQcm90b25WUE4gUm9vdCBDQTCCAiIwDQYJKoZIhvcN
AQEBBQADggIPADCCAgoCggIBAMkUT7zMUS5C+NjQ7YoGpVFlfbN9HFgG4JiKfHB8
QxnPPRgyTi0zVOAj1ImsRilauY8Ddm5dQtd8qcApoz6oCx5cFiiSQG2uyhS/59Zl
5wqIkw1o+CgwZgeWkq04lcrxhhfPgJZRFjrYVezy/Z2Ssd18s3/FFNQ+2iV1KC2K
z8eSPr50u+l9vEKsKiNGkJTdlWjoDKZM2C15i/h8Smi+PdJlx7WMTtYoVC1Fzq0r
aCPDQl18kspu11b6d8ECPWghKcDIIKuA0r0nGqF1GvH1AmbC/xUaNrKgz9AfioZL
MP/l22tVG3KKM1ku0eYHX7NzNHgkM2JKnBBannImQQBGTAcvvUlnfF3AHx4vzx7H
ahpBz8ebThx2uv+vzu8lCVEcKjQObGwLbAONJN2enug8hwSSZQv7tz7onDQWlYh0
El5fnkrEQGbukNnSyOqTwfobvBllIPzBqdO38eZFA0YTlH9plYjIjPjGl931lFAA
3G9t0x7nxAauLXN5QVp1yoF1tzXc5kN0SFAasM9VtVEOSMaGHLKhF+IMyVX8h5Iu
IRC8u5O672r7cHS+Dtx87LjxypqNhmbf1TWyLJSoh0qYhMr+BbO7+N6zKRIZPI5b
MXc8Be2pQwbSA4ZrDvSjFC9yDXmSuZTyVo6Bqi/KCUZeaXKof68oNxVYeGowNeQd
g/znAgMBAAGjUzBRMB0GA1UdDgQWBBR44WtTuEKCaPPUltYEHZoyhJo+4TAfBgNV
HSMEGDAWgBR44WtTuEKCaPPUltYEHZoyhJo+4TAPBgNVHRMBAf8EBTADAQH/MA0G
CSqGSIb3DQEBCwUAA4ICAQBBmzCQlHxOJ6izys3TVpaze+rUkA9GejgsB2DZXIcm
4Lj/SNzQsPlZRu4S0IZV253dbE1DoWlHanw5lnXwx8iU82X7jdm/5uZOwj2NqSqT
bTn0WLAC6khEKKe5bPTf18UOcwN82Le3AnkwcNAaBO5/TzFQVgnVedXr2g6rmpp9
gdedeEl9acB7xqfYfkrmijqYMm+xeG2rXaanch3HjweMDuZdT/Ub5G6oir0Kowft
lA1ytjXRg+X+yWymTpF/zGLYfSodWWjMKhpzZtRJZ+9B0pWXUyY7SuCj5T5SMIAu
x3NQQ46wSbHRolIlwh7zD7kBgkyLe7ByLvGFKa2Vw4PuWjqYwrRbFjb2+EKAwPu6
VTWz/QQTU8oJewGFipw94Bi61zuaPvF1qZCHgYhVojRy6KcqncX2Hx9hjfVxspBZ
DrVH6uofCmd99GmVu+qizybWQTrPaubfc/a2jJIbXc2bRQjYj/qmjE3hTlmO3k7V
EP6i8CLhEl+dX75aZw9StkqjdpIApYwX6XNDqVuGzfeTXXclk4N4aDPwPFM/Yo/e
KnvlNlKbljWdMYkfx8r37aOHpchH34cv0Jb5Im+1H07ywnshXNfUhRazOpubJRHn
bjDuBwWS1/Vwp5AJ+QHsPXhJdl3qHc1szJZVJb3VyAWvG/bWApKfFuZX18tiI4N0
EA==
-----END CERTIFICATE-----"""


def sanitize_region_for_filename(region_name):
    name = region_name.lower()
    name = name.replace(' ', '-')
    name = ''.join(c if c.isalnum() or c == '-' else '' for c in name)
    name = '-'.join(filter(None, name.split('-')))
    return name


def get_pia_openvpn_config(region_name, protocol, server_list):
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


@app.route('/pia/regions')
def pia_regions():
    try:
        pia = piawg()
        regions = sorted(pia.server_list.keys())
        logger.info(f"Retrieved {len(regions)} PIA regions")
        return jsonify(regions)
    except Exception as e:
        logger.error(f"Failed to retrieve PIA regions: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/proton/regions')
def proton_regions():
    try:
        servers = proton_server_list()
        logger.info(f"Retrieved {len(servers)} ProtonVPN servers")
        return jsonify(servers)
    except Exception as e:
        logger.error(f"Failed to retrieve ProtonVPN servers: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/pia/generate', methods=['POST'])
def pia_generate():
    temp_file = None
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        region = request.form.get('region')
        config_type = request.form.get('config_type', 'wireguard')

        if not all([username, password, region]):
            return jsonify({'error': 'All fields are required'}), 400

        sanitized_region = sanitize_region_for_filename(region)
        pia = piawg()

        if region not in pia.server_list:
            return jsonify({'error': f'Invalid region: {region}'}), 400

        if config_type in ('openvpn_udp', 'openvpn_tcp'):
            protocol = 'tcp' if config_type == 'openvpn_tcp' else 'udp'
            logger.info(f"Generating PIA OpenVPN {protocol.upper()} for region: {region}")
            config_content, error = get_pia_openvpn_config(region, protocol, pia.server_list)
            if error:
                return jsonify({'error': error}), 500
            config_content += f"\n<auth-user-pass>\n{username}\n{password}\n</auth-user-pass>\n"
            tunnel_name = f'PIA-{sanitized_region}-{protocol.upper()}'
            suffix = '.ovpn'
        else:
            logger.info(f"Generating PIA WireGuard config for region: {region}")
            pia.generate_keys()
            pia.set_region(region)
            if not pia.get_token(username, password):
                return jsonify({'error': 'Invalid credentials or authentication failed'}), 401
            status, response = pia.addkey()
            if not status:
                return jsonify({'error': 'Failed to register key with server'}), 500
            tunnel_name = f'PIA-{sanitized_region}'
            config_content = f"""[Interface]
Address = {pia.connection['peer_ip']}
PrivateKey = {pia.privatekey}
DNS = {pia.connection['dns_servers'][0]},{pia.connection['dns_servers'][1]}

# {tunnel_name}

[Peer]
PublicKey = {pia.connection['server_key']}
Endpoint = {pia.connection['server_ip']}:1337
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
            suffix = '.conf'

        with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
            f.write(config_content)
            temp_file = f.name

        filename = f'{tunnel_name}{suffix}'
        response = send_file(temp_file, as_attachment=True, download_name=filename, mimetype='text/plain')

        @response.call_on_close
        def cleanup():
            try:
                if temp_file and os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                logger.error(f"Cleanup error: {e}")

        return response

    except Exception as e:
        logger.error(f"PIA generate error: {str(e)}")
        if temp_file and os.path.exists(temp_file):
            try:
                os.unlink(temp_file)
            except Exception:
                pass
        return jsonify({'error': str(e)}), 500


@app.route('/proton/generate', methods=['POST'])
def proton_generate():
    temp_file = None
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        server = request.form.get('server')
        protocol = request.form.get('protocol', 'udp')

        if not all([username, password, server]):
            return jsonify({'error': 'All fields are required'}), 400

        logger.info(f"Generating ProtonVPN {protocol.upper()} config for server: {server}")

        config_content, error = generate_proton_config(server, protocol, username, password)
        if error:
            return jsonify({'error': error}), 500

        sanitized = sanitize_region_for_filename(server)
        filename = f'ProtonVPN-{sanitized}-{protocol.upper()}.ovpn'

        with tempfile.NamedTemporaryFile(mode='w', suffix='.ovpn', delete=False) as f:
            f.write(config_content)
            temp_file = f.name

        response = send_file(temp_file, as_attachment=True, download_name=filename, mimetype='text/plain')

        @response.call_on_close
        def cleanup():
            try:
                if temp_file and os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                logger.error(f"Cleanup error: {e}")

        return response

    except Exception as e:
        logger.error(f"ProtonVPN generate error: {str(e)}")
        if temp_file and os.path.exists(temp_file):
            try:
                os.unlink(temp_file)
            except Exception:
                pass
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
