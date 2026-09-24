import hashlib
from pathlib import Path
from typing import Callable, Optional


SITE_ROOT = Path("/var/www/remnawave-node")


CSS = """*{box-sizing:border-box}html{background:#0c1117;color:#e7edf4;font:16px/1.6 Inter,ui-sans-serif,system-ui,sans-serif}body{margin:0;min-height:100vh}main{max-width:920px;margin:0 auto;padding:72px 24px}nav{display:flex;gap:22px;margin-bottom:86px}nav a{color:#aab8c7;text-decoration:none}nav a:hover{color:#fff}.eyebrow{color:#77d2b5;letter-spacing:.16em;text-transform:uppercase;font-size:.76rem}.hero{max-width:650px}.hero h1{font-size:clamp(2.5rem,7vw,5.6rem);line-height:.98;letter-spacing:-.065em;margin:18px 0}.lead{color:#aab8c7;font-size:1.25rem;max-width:580px}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:64px}.grid--offset{grid-template-columns:1.3fr .85fr .85fr}.grid--compact{gap:8px;margin-top:42px}.card{border:1px solid #26323f;border-radius:16px;padding:20px;background:#111923}.card strong{display:block;font-size:1.2rem}.signal{border-left:3px solid #77d2b5;margin-top:58px;padding:4px 0 4px 22px}.signal strong{display:block;font-size:1.35rem}.ok{color:#77d2b5}.muted{color:#718092}footer{margin-top:100px;color:#718092;font-size:.9rem}@media(max-width:680px){main{padding-top:34px}nav{margin-bottom:58px}.grid,.grid--offset{grid-template-columns:1fr}}"""

PALETTE = ("#77d2b5", "#8bd3ff", "#f4c37d", "#c5a7ff", "#f19bb5")


def _brand(identity: str = "default") -> str:
    token = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:6].upper()
    return f"Northline {token}"


def _css(identity: str) -> str:
    digest = hashlib.sha256(identity.encode("utf-8")).digest()
    accent = PALETTE[digest[0] % len(PALETTE)]
    return CSS.replace("#77d2b5", accent)


def _layout_variant(identity: str) -> int:
    return hashlib.sha256(identity.encode("utf-8")).digest()[1] % 4


def _status_extra(variant: int) -> str:
    if variant == 1:
        return '<div class="grid grid--offset"><div class="card"><strong class="ok">Available</strong><span class="muted">Core</span></div><div class="card"><strong class="ok">Clear</strong><span class="muted">HTTP</span></div><div class="card"><strong class="ok">Ready</strong><span class="muted">Queue</span></div></div>'
    if variant == 2:
        return '<div class="signal"><strong class="ok">Operating normally</strong><span class="muted">The latest service check completed without errors.</span></div>'
    if variant == 3:
        return '<div class="grid grid--compact"><div class="card"><strong class="ok">01</strong><span class="muted">Availability</span></div><div class="card"><strong class="ok">02</strong><span class="muted">Response</span></div><div class="card"><strong class="ok">03</strong><span class="muted">Readiness</span></div></div>'
    return '<div class="grid"><div class="card"><strong class="ok">Online</strong><span class="muted">Network</span></div><div class="card"><strong class="ok">Online</strong><span class="muted">HTTP</span></div><div class="card"><strong class="ok">Ready</strong><span class="muted">Operations</span></div></div>'


def _html(title: str, message: str, active: str, brand: str, variant: int) -> str:
    links = "".join(f'<a class="{"ok" if active == key else ""}" href="{href}">{label}</a>' for key, href, label in (("status", "/", "Status"), ("about", "/about/", "About"), ("contact", "/contact/", "Contact")))
    extra = _status_extra(variant) if active == "status" else ""
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="description" content="{brand}"><title>{title} · {brand}</title><link rel="stylesheet" href="/assets/site.css"></head>
<body><main class="layout-{variant}"><nav><a href="/" aria-label="{brand}">{brand}</a>{links}</nav><section class="hero"><span class="eyebrow">{brand}</span><h1>{title}</h1><p class="lead">{message}</p>{extra}</section><footer>Independent infrastructure services · {2026}</footer></main></body></html>'''


def generate_site(root: Path = SITE_ROOT, identity: str = "default", on_created: Optional[Callable[[Path], None]] = None) -> None:
    brand = _brand(identity)
    variant = _layout_variant(identity)
    pages = {
        "index.html": (brand, "Independent infrastructure services.", "status"),
        "about/index.html": ("About Northline", "Practical systems engineering for dependable digital services.", "about"),
        "status/index.html": ("Service Status", "All systems operational.", "status"),
        "contact/index.html": ("Contact", "Operational notices are published here when required.", "contact"),
        "404.html": ("Page not found", "The requested page is not available.", "error"),
    }
    root_existed = root.exists()
    root.mkdir(parents=True, exist_ok=True)
    if not root_existed and on_created:
        on_created(root)
    (root / "assets").mkdir(exist_ok=True)
    (root / "assets" / "site.css").write_text(_css(identity), encoding="utf-8")
    (root / "robots.txt").write_text("User-agent: *\nDisallow:\n", encoding="utf-8")
    for relative, values in pages.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(_html(*values, brand=brand, variant=variant), encoding="utf-8")
