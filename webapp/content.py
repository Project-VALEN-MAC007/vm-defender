"""Public-facing content shared by the production site and the honeypot.

The same code and templates run in both places. What differs is the backend
(see backends/): the production site reads real company data, the honeypot
reads an isolated decoy data set. Public pages are therefore byte-for-byte the
same between the two, so a visitor who is redirected cannot tell from the pages
alone — which is the point of the Web Honeypot.

Standard library only, to match the rest of TRAP.
"""
from __future__ import annotations

from html import escape

COMPANY_FALLBACK = "Acme Logistics"

# robots.txt is part of the public site, so both backends serve the same file.
# Keep it identical to the Rabbit Hole robots node (tests/test_webapp.py checks).
ROBOTS_TXT = "User-agent: *\nDisallow: /backup/\nDisallow: /api/docs\nDisallow: /cgi-bin/\n"

NAV = (("/", "Home"), ("/about", "About"), ("/services", "Services"),
       ("/news", "News"), ("/contact", "Contact"), ("/login", "Sign in"))


def page(company: str, title: str, body: str, year: int) -> str:
    links = "".join(f'<a href="{escape(path)}">{escape(label)}</a>' for path, label in NAV)
    safe_company = escape(company)
    return (
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        f"<title>{escape(title)} · {safe_company}</title>\n"
        "<link rel=\"stylesheet\" href=\"/static/site.css\">\n</head>\n<body>\n"
        f"<header class=\"site-header\"><div class=\"wrap\"><a class=\"brand\" href=\"/\">{safe_company}</a>"
        f"<nav>{links}</nav></div></header>\n"
        f"<main class=\"wrap\">\n{body}\n</main>\n"
        f"<footer class=\"site-footer\"><div class=\"wrap\">&copy; {year} {safe_company} Co., Ltd. "
        "· All rights reserved.</div></footer>\n</body>\n</html>\n"
    )


def home(company: str) -> str:
    return (
        f"<section class=\"hero\"><h1>Freight that arrives on schedule</h1>"
        f"<p>{escape(company)} moves road, sea and air freight across the region with "
        "real-time tracking and one account team.</p>"
        "<p><a class=\"cta\" href=\"/services\">Our services</a></p></section>"
        "<section class=\"cards\">"
        "<article><h3>Road freight</h3><p>Daily departures and same-day options across the country.</p></article>"
        "<article><h3>Sea &amp; air</h3><p>FCL, LCL and air consolidation with customs handling.</p></article>"
        "<article><h3>Warehousing</h3><p>Bonded and ambient storage with pick-and-pack fulfilment.</p></article>"
        "</section>"
    )


def about(company: str) -> str:
    return (
        "<h1>About us</h1>"
        f"<p>{escape(company)} has handled regional logistics since 2009. Our teams in "
        "three distribution centres coordinate freight for manufacturers, retailers and "
        "e-commerce sellers.</p>"
        "<p>We are ISO 9001 certified and operate a 24-hour control room.</p>"
    )


def services(company: str) -> str:
    rows = (("Road freight", "LTL and FTL, with tail-lift and temperature-controlled options."),
            ("Sea freight", "FCL/LCL via major regional ports with door delivery."),
            ("Air freight", "Standard and express air with consolidation."),
            ("Warehousing", "Bonded storage, cross-dock and fulfilment."))
    items = "".join(f"<article><h3>{escape(t)}</h3><p>{escape(d)}</p></article>" for t, d in rows)
    return "<h1>Services</h1><section class=\"cards\">" + items + "</section>"


def news_index(company: str, articles: list[dict]) -> str:
    items = "".join(
        f'<li><a href="/news/{escape(str(a["slug"]))}">{escape(a["title"])}</a>'
        f'<span class="date">{escape(a["date"])}</span></li>' for a in articles)
    return "<h1>News</h1><ul class=\"news\">" + (items or "<li>No posts yet.</li>") + "</ul>"


def news_article(company: str, article: dict) -> str:
    return (f"<article class=\"post\"><h1>{escape(article['title'])}</h1>"
            f"<p class=\"date\">{escape(article['date'])}</p>"
            f"<p>{escape(article['body'])}</p></article>")


def contact(company: str, sent: bool = False, name: str = "") -> str:
    note = (f"<p class=\"success\">Thank you, {escape(name)}. Our team will reply by email.</p>"
            if sent else "")
    return (
        "<h1>Contact us</h1>" + note +
        "<form method=\"post\" action=\"/contact\" class=\"contact-form\">"
        "<label>Name<input name=\"name\" required maxlength=\"100\"></label>"
        "<label>Email<input name=\"email\" type=\"email\" required maxlength=\"120\"></label>"
        "<label>Message<textarea name=\"message\" required maxlength=\"2000\"></textarea></label>"
        "<button type=\"submit\">Send message</button></form>"
    )


def login(company: str, error: str = "") -> str:
    note = f"<p class=\"error\">{escape(error)}</p>" if error else ""
    return (
        "<h1>Customer sign in</h1>" + note +
        "<form method=\"post\" action=\"/login\" class=\"login-form\">"
        "<label>Username<input name=\"username\" required maxlength=\"100\" autocomplete=\"username\"></label>"
        "<label>Password<input name=\"password\" type=\"password\" required maxlength=\"200\" "
        "autocomplete=\"current-password\"></label>"
        "<button type=\"submit\">Sign in</button></form>"
    )


def portal(company: str, display_name: str, shipments: list[dict]) -> str:
    rows = "".join(
        f"<tr><td>{escape(s['ref'])}</td><td>{escape(s['origin'])} &rarr; {escape(s['destination'])}</td>"
        f"<td>{escape(s['status'])}</td><td>{escape(s['eta'])}</td></tr>" for s in shipments)
    return (
        f"<h1>Welcome, {escape(display_name)}</h1>"
        "<p>Your recent shipments:</p>"
        "<table class=\"shipments\"><thead><tr><th>Ref</th><th>Route</th><th>Status</th><th>ETA</th></tr></thead>"
        f"<tbody>{rows or '<tr><td colspan=4>No shipments.</td></tr>'}</tbody></table>"
        "<p><a href=\"/logout\">Sign out</a></p>"
    )


NOT_FOUND_BODY = "<h1>Page not found</h1><p>The page you requested does not exist.</p>"

SITE_CSS = (
    ":root{--ink:#1f2933;--muted:#6b7280;--accent:#0f5fa6;--line:#e5e7eb}"
    "*{box-sizing:border-box}body{margin:0;font-family:Arial,Helvetica,sans-serif;color:var(--ink);line-height:1.5}"
    ".wrap{max-width:960px;margin:0 auto;padding:0 20px}"
    ".site-header{border-bottom:1px solid var(--line)}.site-header .wrap{display:flex;align-items:center;"
    "justify-content:space-between;flex-wrap:wrap;gap:8px;padding-top:14px;padding-bottom:14px}"
    ".brand{font-weight:700;font-size:20px;color:var(--accent);text-decoration:none}"
    "nav a{margin-left:16px;color:var(--ink);text-decoration:none;font-size:14px}nav a:hover{color:var(--accent)}"
    "main.wrap{padding-top:28px;padding-bottom:40px}h1{font-size:28px}"
    ".hero{padding:24px 0}.cta{display:inline-block;margin-top:8px;background:var(--accent);color:#fff;"
    "padding:10px 18px;border-radius:6px;text-decoration:none}"
    ".cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-top:16px}"
    ".cards article{border:1px solid var(--line);border-radius:8px;padding:16px}"
    "ul.news{list-style:none;padding:0}ul.news li{display:flex;justify-content:space-between;"
    "border-bottom:1px solid var(--line);padding:10px 0}.date{color:var(--muted);font-size:13px}"
    "form label{display:block;margin:12px 0;font-size:14px}form input,form textarea{display:block;width:100%;"
    "padding:8px;margin-top:4px;border:1px solid var(--line);border-radius:6px;font-size:14px}"
    "form textarea{min-height:120px}button{background:var(--accent);color:#fff;border:0;padding:10px 18px;"
    "border-radius:6px;font-size:14px;cursor:pointer}"
    "table.shipments{width:100%;border-collapse:collapse;margin-top:12px}"
    "table.shipments th,table.shipments td{border:1px solid var(--line);padding:8px;text-align:left;font-size:14px}"
    ".success{color:#047857}.error{color:#b91c1c}.site-footer{border-top:1px solid var(--line);color:var(--muted);"
    "font-size:13px}.site-footer .wrap{padding:18px 20px}"
)
