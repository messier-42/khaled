# khaled Documentation

[![Built with Starlight](https://astro.badg.es/v2/built-with-starlight/tiny.svg)](https://starlight.astro.build)

This is the source for the documentation for khaled, a reference
implementation of a Key Server as described in the
[CABE Architecture](https://cabespec.org/spec/arch/). The documentation is
kept in the same repository as khaled so it can be versioned synchronously
with the server code.

## Commands

All commands are run from this directory (`doc/site/`) in a terminal:

| Command                   | Action                                           |
| :------------------------ | :----------------------------------------------- |
| `npm install`             | Installs dependencies                            |
| `npm run dev`             | Starts local dev server at `localhost:4321`      |
| `npm run build`           | Build your production site to `./dist/`          |
| `npm run preview`         | Preview your build locally, before deploying     |
| `npm run astro ...`       | Run CLI commands like `astro add`, `astro check` |
| `npm run astro -- --help` | Get help using the Astro CLI                     |

## Static build

The `scripts/build-static` script uses Podman to produce a static,
self-contained docsite archive suitable for hosting or for shipping as an
OCI image. It supports two modes:

- `offline` (default) — crawls the rendered site with `wget` and rewrites
  links so the archive can be opened directly from a filesystem.
- `online` — emits the site unchanged, suitable for hosting behind a web
  server.

Usage:

```
./scripts/build-static out.tar.gz [prefix-name] [online|offline]
```

## Releases

If `RELEASE_INFO` is set (or `../../build/release-info/releases.json` exists),
a "Releases" section is added to the sidebar that is populated from JSON
dumps produced by `scripts/get-release-json` at the root of the repo. This is
automated in CI on `master`.
