# Documentation site (`docs/`)

Static **HTML** reference for [GitHub Pages](https://docs.github.com/en/pages)
(Source: Deploy from a branch → folder `/docs`).

- Entry: [`index.html`](index.html)
- Styles: [`assets/site.css`](assets/site.css)
- [`.nojekyll`](.nojekyll) so Pages serves assets as-is

If you regenerate from Markdown drafts, use
[`scripts/md_docs_to_html.py`](../scripts/md_docs_to_html.py) (requires `pandoc`).
The published tree is HTML-only.
