# Alfresco SBOM Generator

Generate a **Software Bill of Materials (SBOM)** for any Alfresco Docker image in one command. The tool wraps [Anchore Syft](https://github.com/anchore/syft) with a thin Python script and a Makefile so you get a clean HTML report instead of raw JSON—and it applies the whitespace fixes needed for reliable parsing.

## Why use this?

* One‑liner reports – `make run IMAGE=alfresco/alfresco-content-repository-community:25.1.0` drops a browsable HTML SBOM in `reports/`.
* License coverage at a glance – the script flags packages without licensing info.
* Pluggable templates – supply any Syft template (we ship a flat one) to keep the parser screaming fast.
* Opinionated defaults – sane exclusions (`/lib`, `/var`), colourised CLI output, zero‑config Docker pulls.

## Prerequisites

| Tool   | Tested Version | Purpose                           |
| ------ | -------------- | --------------------------------- |
| Docker | `24.0+`        | pulls & caches the Alfresco image |
| Syft   | `1.2.0`        | extracts the package list         |
| Python | `3.9+`         | runs `sbom_generator.py`          |
| Make   | any GNU Make   | gloats over your clipboard        |

> **Tip:** on macOS, install everything with Homebrew: `brew install syft make`.

## Quick‑start

```bash
# 1. Clone the repo
$ git clone https://github.com/your‑org/alfresco‑sbom‑generator.git
$ cd alfresco‑sbom‑generator

# 2. Generate the template once (adds the mandatory newline!)
$ make create-template

# 3. Run against any Alfresco image
$ make run IMAGE=alfresco/alfresco-content-repository-community:25.1.0

# 4. Open the report
$ open reports/sbom_alfresco_alfresco-content-repository-community_25.1.0.html
```

## Project layout

```bash
.
├── sbom_generator.py        # tiny wrapper around Syft
├── Makefile                 # UX sugar
├── templates/
│   └── detailed.tmpl        # flat Syft template (one package per line)
├── reports/                 # HTML output lands here (git‑ignored)
└── README.md
```

## Custom templates

Syft’s Go templates are powerful but *very* whitespace‑sensitive. We ship a safe template that ends every artifact with a line‑break **and** keeps dashes from trimming it:

```gotemplate
{{- range .artifacts}}
{{ .name }}:{{ .version }}:{{ .purl }} - {{ range .licenses }}{{ .value }}{{ end }}
{{- end}}
```

To use your own:

```bash
$ make run-with-template \
      IMAGE=alfresco/alfresco-search-services:2.11.0 \
      TEMPLATE=my.tmpl
```

> **Important** — if you modify the template, keep the newline outside any `{{- ... -}}` pair or the Python regex will only capture the first package.

## Contributing

Issues and PRs welcome! Please run `make lint` before raising a pull request.

## License

Apache 2.0 — see `LICENSE` for details.