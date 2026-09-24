from pathlib import Path


APP_NAME = "Remnawave Node Installer"
APP_SLUG = "remnawave-node"
NODE_CONTAINER = "remnanode"
NODE_IMAGE = "remnawave/node:3.4.1"
NODE_PORT = 2222
COVER_SOCKET = "/dev/shm/nginx.sock"
NODE_DIR = Path("/opt/remnanode")
INSTALLER_DIR = Path("/opt/remnawave-node-installer")
STATE_DIR = Path("/var/lib/remnawave-node")
STATE_FILE = STATE_DIR / "install-state.json"
BACKUP_DIR = STATE_DIR / "backups"
LOG_DIR = Path("/var/log/remnawave-node")
INSTALLER_LOG = LOG_DIR / "installer.log"
NODE_LOG_DIR = Path("/var/log/remnanode")
NGINX_SITE_NAME = "remnawave-node"
NGINX_AVAILABLE = Path("/etc/nginx/sites-available") / f"{NGINX_SITE_NAME}.conf"
NGINX_ENABLED = Path("/etc/nginx/sites-enabled") / f"{NGINX_SITE_NAME}.conf"
FAIL2BAN_CONFIG = Path("/etc/fail2ban/jail.d") / f"{NGINX_SITE_NAME}.conf"
LOGROTATE_CONFIG = Path("/etc/logrotate.d") / NGINX_SITE_NAME
CERTBOT_LIVE_DIR = Path("/etc/letsencrypt/live")
DEFAULT_PANEL_IP_ENV = Path("/etc/remnawave-node/config.env")
RENEWAL_HOOK = Path("/etc/letsencrypt/renewal-hooks/deploy/remnawave-node-reload")

SUPPORTED_DISTROS = {"ubuntu", "debian"}

MANAGED_PATHS = [
    NODE_DIR,
    INSTALLER_DIR,
    STATE_DIR,
    LOG_DIR,
    NODE_LOG_DIR,
    NGINX_AVAILABLE,
    NGINX_ENABLED,
    FAIL2BAN_CONFIG,
    LOGROTATE_CONFIG,
]
