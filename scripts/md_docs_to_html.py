#!/usr/bin/env python3
"""Convert docs/*.md to GitHub Pages HTML. Run from repo root."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

NAV = [
    ("Start", [
        ("index.html", "Home"),
        ("getting-started.html", "Getting started"),
        ("architecture.html", "Architecture"),
    ]),
    ("Core", [
        ("services.html", "Services"),
        ("clients.html", "Clients"),
        ("composition.html", "Composition"),
        ("runtime-options.html", "Runtime options"),
    ]),
    ("Protocols", [
        ("tls.html", "TLS"),
        ("http/overview.html", "HTTP overview"),
        ("http/server.html", "HTTP server"),
        ("http/client.html", "HTTP client"),
        ("quic-h3.html", "QUIC / H3"),
        ("dns.html", "DNS"),
        ("webdav.html", "WebDAV"),
        ("websocket.html", "WebSocket"),
        ("grpc.html", "gRPC"),
        ("ftp.html", "FTP"),
        ("smtp.html", "SMTP"),
        ("mailbox.html", "Mailbox"),
    ]),
    ("Cross-cutting", [
        ("auth.html", "Auth"),
        ("access-control.html", "Access control"),
        ("telemetry.html", "Telemetry"),
    ]),
    ("Cookbook", [
        ("cookbook/echo.html", "Echo"),
        ("cookbook/tls-echo.html", "TLS echo"),
        ("cookbook/http-hello-get.html", "HTTP hello / get"),
        ("cookbook/dns-proxy.html", "DNS proxy"),
        ("cookbook/webdav.html", "WebDAV"),
        ("cookbook/websocket.html", "WebSocket"),
        ("cookbook/grpc.html", "gRPC"),
        ("cookbook/ftp.html", "FTP"),
        ("cookbook/smtp.html", "SMTP"),
    ]),
]

# Meta readme for maintainers — not a Pages page.
SKIP_MD = {"README.md"}


def depth_prefix(rel: Path) -> str:
    n = len(rel.parts) - 1
    return "../" * n if n else ""


def nav_html(current: str, prefix: str) -> str:
    parts = ['<nav class="nav" aria-label="Documentation">']
    parts.append(f'<a class="brand" href="{prefix}index.html">Hopf</a>')
    parts.append('<p class="tag">Networking framework reference</p>')
    for section, links in NAV:
        parts.append(f"<h2>{section}</h2><ul>")
        for href, label in links:
            cur = ' aria-current="page"' if href == current else ""
            parts.append(f'<li><a href="{prefix}{href}"{cur}>{label}</a></li>')
        parts.append("</ul>")
    parts.append("</nav>")
    return "\n".join(parts)


def rewrite_links(html: str) -> str:
    # Markdown links to .md → .html; README.md → index.html
    html = re.sub(
        r'href="([^"]*?)/README\.md"',
        r'href="\1/index.html"',
        html,
    )
    html = re.sub(r'href="README\.md"', 'href="index.html"', html)

    def repl(m):
        path, frag = m.group(1), m.group(2) or ""
        leaf = path.rsplit("/", 1)[-1]
        if leaf in ("PLAN", "TRANCHES"):
            return f'href="{path}.md{frag}"'
        return f'href="{path}.html{frag}"'

    html = re.sub(r'href="([^"]+?)\.md(#[^"]*)?"', repl, html)
    return html


def extract_title(md: str, fallback: str) -> tuple[str, str | None]:
    lines = md.splitlines()
    title = fallback
    lead = None
    if lines and lines[0].startswith("# "):
        title = lines[0][2:].strip()
        # first non-empty paragraph after title as lead
        body = []
        for line in lines[1:]:
            if line.startswith("#"):
                break
            if line.strip():
                body.append(line.strip())
                break
        if body:
            lead = body[0]
    return title, lead


def pandoc_body(md_path: Path) -> str:
    # Strip leading H1 (page title comes from template header)
    text = md_path.read_text()
    lines = text.splitlines()
    if lines and lines[0].startswith("# "):
        text = "\n".join(lines[1:]).lstrip("\n")
    proc = subprocess.run(
        [
            "pandoc",
            "-f",
            "markdown",
            "-t",
            "html5",
            "--wrap=none",
        ],
        input=text,
        capture_output=True,
        text=True,
        check=True,
    )
    return rewrite_links(proc.stdout)


def page(rel: Path, md_path: Path, out_name: str) -> Path:
    md = md_path.read_text()
    fallback = out_name.replace(".html", "").replace("-", " ").title()
    title, lead = extract_title(md, fallback)
    prefix = depth_prefix(rel)
    current = str(rel).replace("\\", "/")
    if current.endswith("README.md") or current == "README.md":
        current = "index.html"
    else:
        current = current[:-3] + ".html" if current.endswith(".md") else current

    body = pandoc_body(md_path)
    lead_html = f'<p class="lead">{lead}</p>' if lead else ""
    # Escape title minimally
    title_esc = (
        title.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title_esc} — Hopf</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Literata:opsz,wght@7..72,400;7..72,600;7..72,700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="{prefix}assets/site.css">
</head>
<body>
  <div class="layout">
    {nav_html(current, prefix)}
    <main class="main">
      <header>
        <h1>{title_esc}</h1>
        {lead_html}
      </header>
      {body}
      <p class="footer">
        Architecture: <a href="https://github.com/cpkb-bluezoo/hopf/blob/main/PLAN.md">PLAN.md</a> ·
        Tranches: <a href="https://github.com/cpkb-bluezoo/hopf/blob/main/TRANCHES.md">TRANCHES.md</a> ·
        <a href="https://github.com/cpkb-bluezoo/hopf">GitHub</a>
      </p>
    </main>
  </div>
</body>
</html>
"""
    out = DOCS / rel
    if out.name == "README.md":
        out = out.with_name("index.html")
    else:
        out = out.with_suffix(".html")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html)
    print("wrote", out.relative_to(ROOT))
    return out


def html_current_from_path(html_path: Path) -> str:
    rel = html_path.relative_to(DOCS).as_posix()
    return rel


def refresh_navs() -> None:
    """Rewrite <nav>…</nav> in every docs HTML page from NAV."""
    nav_re = re.compile(r"<nav class=\"nav\"[^>]*>.*?</nav>", re.DOTALL)
    for html_path in sorted(DOCS.rglob("*.html")):
        text = html_path.read_text()
        current = html_current_from_path(html_path)
        prefix = depth_prefix(html_path.relative_to(DOCS))
        new_nav = nav_html(current, prefix)
        if not nav_re.search(text):
            print("skip (no nav):", html_path.relative_to(ROOT), file=sys.stderr)
            continue
        updated = nav_re.sub(new_nav, text, count=1)
        if updated != text:
            html_path.write_text(updated)
            print("nav", html_path.relative_to(ROOT))


def main() -> None:
    md_files = sorted(
        p for p in DOCS.rglob("*.md") if p.relative_to(DOCS).as_posix() not in SKIP_MD
    )
    for md in md_files:
        rel = md.relative_to(DOCS)
        page(rel, md, md.stem + ".html")
    # remove markdown sources (HTML is canonical); keep docs/README.md
    for md in md_files:
        md.unlink()
        print("removed", md.relative_to(ROOT))
    refresh_navs()
    (DOCS / ".nojekyll").write_text("")
    print("done")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--nav-only":
        refresh_navs()
        print("done")
    else:
        main()
