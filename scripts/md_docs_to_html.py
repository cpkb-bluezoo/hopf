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
        ("pop3.html", "POP3"),
        ("imap.html", "IMAP"),
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
        ("cookbook/pop3.html", "POP3"),
    ]),
]

# Meta readme for maintainers — not a Pages page.
SKIP_MD = {"README.md"}


def depth_prefix(rel: Path) -> str:
    n = len(rel.parts) - 1
    return "../" * n if n else ""


def nav_html(current: str, prefix: str) -> str:
    parts = ['<nav class="nav" aria-label="Documentation">']
    parts.append(
        f'<a class="logo" href="{prefix}index.html">'
        f'<img src="{prefix}assets/hopf.png" alt="Hopf" width="220" height="206">'
        f"</a>"
    )
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
        # Full first paragraph after title (until blank line or heading)
        parts: list[str] = []
        for line in lines[1:]:
            if line.startswith("#"):
                break
            if not line.strip():
                if parts:
                    break
                continue
            parts.append(line.strip())
        if parts:
            lead = " ".join(parts)
    return title, lead


def inline_md(text: str, prefix: str = "") -> str:
    """Minimal inline markdown for leads (links, code spans, bold)."""
    text = (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )

    def link_repl(m: re.Match[str]) -> str:
        label, href = m.group(1), m.group(2)
        if not href.startswith(("http://", "https://", "#", "/")):
            if href.endswith(".md"):
                href = href[:-3] + ".html"
            elif ".md#" in href:
                href = href.replace(".md#", ".html#")
            href = prefix + href
        return f'<a href="{href}">{label}</a>'

    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", link_repl, text)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    return text


def wrap_toc(html: str) -> str:
    """Wrap ## Contents heading + following <ul> in <div class="toc">."""
    return re.sub(
        r"(<h2[^>]*>Contents</h2>\s*)(<ul>.*?</ul>)",
        r'<div class="toc">\1\2</div>',
        html,
        count=1,
        flags=re.DOTALL | re.IGNORECASE,
    )


def pandoc_body(md_path: Path, strip_lead: bool = True) -> str:
    # Strip leading H1 (page title comes from template header)
    text = md_path.read_text()
    lines = text.splitlines()
    if lines and lines[0].startswith("# "):
        lines = lines[1:]
    # Drop blank lines after title
    while lines and not lines[0].strip():
        lines = lines[1:]
    # Drop first paragraph (used as header lead) until blank line or heading
    if strip_lead and lines and not lines[0].startswith("#"):
        i = 0
        while i < len(lines) and lines[i].strip() and not lines[i].startswith("#"):
            i += 1
        lines = lines[i:]
        while lines and not lines[0].strip():
            lines = lines[1:]
    text = "\n".join(lines).lstrip("\n")
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
    return wrap_toc(rewrite_links(proc.stdout))


def page(rel: Path, md_path: Path, out_name: str) -> Path:
    md = md_path.read_text()
    fallback = out_name.replace(".html", "").replace("-", " ").title()
    title, lead = extract_title(md, fallback)
    prefix = depth_prefix(rel)
    current = str(rel).replace("\\", "/")
    if current in ("README.md", "index.md") or current.endswith("/README.md"):
        current = "index.html"
    elif current.endswith(".md"):
        current = current[:-3] + ".html"

    body = pandoc_body(md_path)
    lead_html = f'<p class="lead">{inline_md(lead, prefix)}</p>' if lead else ""
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
        <a href="https://github.com/cpkb-bluezoo/hopf">GitHub</a>
      </p>
    </main>
  </div>
</body>
</html>
"""
    out = DOCS / rel
    if out.name in ("README.md", "index.md"):
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
