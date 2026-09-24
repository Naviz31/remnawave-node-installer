from pathlib import Path


SITE_ROOT = Path("/var/www/remnawave-node")


PAGES = {
    "index.html": ("Northline Systems", "Independent infrastructure services.", "status"),
    "about/index.html": ("About Northline", "Practical systems engineering for dependable digital services.", "about"),
    "status/index.html": ("Service Status", "All systems operational.", "status"),
    "contact/index.html": ("Contact", "Operational notices are published here when required.", "contact"),
    "404.html": ("Page not found", "The requested page is not available.", "error"),
}


CSS = """*{box-sizing:border-box}html{background:#0c1117;color:#e7edf4;font:16px/1.6 Inter,ui-sans-serif,system-ui,sans-serif}body{margin:0;min-height:100vh}main{max-width:920px;margin:0 auto;padding:72px 24px}nav{display:flex;gap:22px;margin-bottom:86px}nav a{color:#aab8c7;text-decoration:none}nav a:hover{color:#fff}.eyebrow{color:#77d2b5;letter-spacing:.16em;text-transform:uppercase;font-size:.76rem}.hero{max-width:650px}.hero h1{font-size:clamp(2.5rem,7vw,5.6rem);line-height:.98;letter-spacing:-.065em;margin:18px 0}.lead{color:#aab8c7;font-size:1.25rem;max-width:580px}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:64px}.card{border:1px solid #26323f;border-radius:16px;padding:20px;background:#111923}.card strong{display:block;font-size:1.2rem}.ok{color:#77d2b5}.muted{color:#718092}footer{margin-top:100px;color:#718092;font-size:.9rem}@media(max-width:680px){main{padding-top:34px}nav{margin-bottom:58px}.grid{grid-template-columns:1fr}}"""


def _html(title: str, message: str, active: str) -> str:
    links = "".join(f'<a class="{"ok" if active == key else ""}" href="{href}">{label}</a>' for key, href, label in (("status", "/"), ("about", "/about/"), ("contact", "/contact/")))
    extra = '<div class="grid"><div class="card"><strong class="ok">Online</strong><span class="muted">Network</span></div><div class="card"><strong class="ok">Online</strong><span class="muted">HTTP</span></div><div class="card"><strong class="ok">Ready</strong><span class="muted">Operations</span></div></div>' if active == "status" else ""
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="description" content="Northline Systems"><title>{title} · Northline Systems</title><link rel="stylesheet" href="/assets/site.css"></head>
<body><main><nav><a href="/" aria-label="Northline Systems">Northline Systems</a>{links}</nav><section class="hero"><span class="eyebrow">Northline Systems</span><h1>{title}</h1><p class="lead">{message}</p>{extra}</section><footer>Independent infrastructure services · {2026}</footer></main></body></html>'''


def generate_site(root: Path = SITE_ROOT) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "assets").mkdir(exist_ok=True)
    (root / "assets" / "site.css").write_text(CSS, encoding="utf-8")
    (root / "robots.txt").write_text("User-agent: *\nDisallow:\n", encoding="utf-8")
    for relative, values in PAGES.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(_html(*values), encoding="utf-8")
