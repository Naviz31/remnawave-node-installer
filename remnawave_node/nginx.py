from .constants import COVER_SOCKET, NGINX_AVAILABLE, NGINX_ENABLED
from .system import CommandRunner


def nginx_config(domain: str, *, certificate: bool) -> str:
    backend_listen = f"listen unix:{COVER_SOCKET} ssl proxy_protocol;" if certificate else f"listen unix:{COVER_SOCKET} proxy_protocol;"
    ssl_block = f'''\n    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;\n    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;\n    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_session_cache shared:SSL:10m;\n''' if certificate else "\n    # TLS is enabled after the HTTP-01 certificate is issued.\n"
    return f'''server_tokens off;

server {{
    listen 80;
    listen [::]:80;
    server_name {domain};
    root /var/www/remnawave-node;
    index index.html;

    location ^~ /.well-known/acme-challenge/ {{
        try_files $uri =404;
    }}

    location / {{
        try_files $uri $uri/ /404.html;
    }}
}}

server {{
    {backend_listen}{ssl_block}
    server_name {domain};
    root /var/www/remnawave-node;
    index index.html;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    gzip on;
    gzip_types text/plain text/css application/javascript application/json image/svg+xml;
    location /assets/ {{
        expires 7d;
        add_header Cache-Control "public, max-age=604800, immutable";
        try_files $uri =404;
    }}
    location / {{
        try_files $uri $uri/ /404.html;
    }}
    error_page 404 /404.html;
}}
'''


def write_nginx_config(domain: str, *, certificate: bool, runner: CommandRunner, backup=None) -> None:
    if backup:
        backup(NGINX_AVAILABLE)
    NGINX_AVAILABLE.parent.mkdir(parents=True, exist_ok=True)
    NGINX_AVAILABLE.write_text(nginx_config(domain, certificate=certificate), encoding="utf-8")
    NGINX_AVAILABLE.chmod(0o644)
    if not NGINX_ENABLED.exists():
        NGINX_ENABLED.parent.mkdir(parents=True, exist_ok=True)
        NGINX_ENABLED.symlink_to(NGINX_AVAILABLE)
    runner.run(["nginx", "-t"], timeout=60)
    runner.run(["systemctl", "enable", "--now", "nginx"], timeout=60)
    runner.run(["systemctl", "reload", "nginx"], timeout=60)
