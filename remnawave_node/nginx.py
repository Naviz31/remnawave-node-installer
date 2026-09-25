from pathlib import Path
from typing import Callable, Optional

from .constants import COVER_SOCKET, DEFAULT_TLS_MODE, DEFAULT_WS_PROXY_PORT, NGINX_AVAILABLE, NGINX_ENABLED, TLS_MODE_NGINX_WS
from .system import CommandRunner


def nginx_config(
    domain: str,
    *,
    certificate: bool,
    tls_mode: str = DEFAULT_TLS_MODE,
    ws_proxy_port: int = DEFAULT_WS_PROXY_PORT,
) -> str:
    if tls_mode not in {DEFAULT_TLS_MODE, TLS_MODE_NGINX_WS}:
        raise ValueError(f"неподдерживаемый TLS_MODE: {tls_mode}")
    backend_listen = f"listen unix:{COVER_SOCKET} ssl proxy_protocol;" if certificate else f"listen unix:{COVER_SOCKET} proxy_protocol;"
    ssl_block = f'''\n    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;\n    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;\n    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_session_cache shared:SSL:10m;\n''' if certificate else "\n    # TLS is enabled after the HTTP-01 certificate is issued.\n"
    ws_server = ""
    if tls_mode == TLS_MODE_NGINX_WS and certificate:
        ws_server = f'''\nserver {{
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name {domain};
    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:WS_TLS:10m;

    error_page 418 = @cover;

    location / {{
        if ($http_upgrade !~* websocket) {{
            return 418;
        }}
        proxy_pass http://127.0.0.1:{ws_proxy_port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_buffering off;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }}

    location @cover {{
        proxy_pass http://127.0.0.1:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }}
}}
'''
    return f'''server {{
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
{ws_server}'''


def write_nginx_config(
    domain: str,
    *,
    certificate: bool,
    runner: CommandRunner,
    tls_mode: str = DEFAULT_TLS_MODE,
    ws_proxy_port: int = DEFAULT_WS_PROXY_PORT,
    backup=None,
    on_created: Optional[Callable[[Path], None]] = None,
) -> None:
    available_existed = NGINX_AVAILABLE.exists()
    enabled_existed = NGINX_ENABLED.exists()
    if backup:
        backup(NGINX_AVAILABLE)
    NGINX_AVAILABLE.parent.mkdir(parents=True, exist_ok=True)
    NGINX_AVAILABLE.write_text(
        nginx_config(domain, certificate=certificate, tls_mode=tls_mode, ws_proxy_port=ws_proxy_port),
        encoding="utf-8",
    )
    if not available_existed and on_created:
        on_created(NGINX_AVAILABLE)
    NGINX_AVAILABLE.chmod(0o644)
    if not NGINX_ENABLED.exists():
        NGINX_ENABLED.parent.mkdir(parents=True, exist_ok=True)
        NGINX_ENABLED.symlink_to(NGINX_AVAILABLE)
        if not enabled_existed and on_created:
            on_created(NGINX_ENABLED)
    runner.run(["nginx", "-t"], timeout=60)
    runner.run(["systemctl", "enable", "--now", "nginx"], timeout=60)
    runner.run(["systemctl", "reload", "nginx"], timeout=60)
