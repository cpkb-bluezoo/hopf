# Documentation site (`docs/`)

Static **HTML** reference for [GitHub Pages](https://docs.github.com/en/pages)
(Source: Deploy from a branch → folder `/docs`).

- Entry: [`index.html`](index.html)
- Styles: [`assets/site.css`](assets/site.css)
- Logo: [`assets/hopf.png`](assets/hopf.png)
- [`.nojekyll`](.nojekyll) so Pages serves assets as-is

Protocol and crate pages are **feature manuals** in the Gumdrop style: RFCs,
supported capabilities, configuration tables for every knob, handler SPIs,
code examples, and limitations. Cookbook pages stay short and point at
`examples/`.

If you regenerate from Markdown drafts, use
[`scripts/md_docs_to_html.py`](../scripts/md_docs_to_html.py) (requires `pandoc`).
The published tree is HTML-only. Use `python3 scripts/md_docs_to_html.py --nav-only`
to refresh the shared sidebar without converting Markdown.
