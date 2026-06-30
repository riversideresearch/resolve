# Docs Website

This website can be iterated on and tested locally by doing the following:

```bash
# in repository root
uv venv # or source .venv/bin/activate if it exists

# installs mkdocs-material, which pulls in mkdocs and the pymdownx
# extensions configured in mkdocs.yml
uv pip install -r docs/requirements.txt

mkdocs serve
```

!!! note
    The site is built with `strict: true`, so any broken internal link or
    nav reference will fail the build. Run `mkdocs build --strict` before
    pushing to catch these early.

This will bring up the site on a local server, that you can live-preview in your browser while you work on it.
