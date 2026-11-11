# Velum Branding Assets

These assets are for future builds. Published preview executables, archives and
release tags are not modified by this source branding update.

## Approved Source

`app-icon.png` is the final user-approved 512x512 RGBA dark-tile logo, without
the green background. It is copied without pixel changes from the clean public
`velum-logo-512-20261112.png` asset.

SHA-256: `d69bfa225ed48b035d3aaea54df25dc39156934b56b6f92ec892863c01cced65`.

The earlier green-corner crop is superseded. The original JPEG/high-resolution
cutout stays private; this tree contains only the metadata-free approved PNG
and mechanical icon derivatives. No AI redraw, vector tracing or new crop.

## Mechanical Conversion

From the application's `app` directory, using its already installed Tauri CLI:

```text
pnpm exec tauri icon src-tauri/icons/app-icon.png --output src-tauri/icons
```

After generation, retain the main 512px `icon.png` as a byte-identical copy of
`app-icon.png`; the standard converter otherwise re-encodes its RGBA values even
at the same size. Platform-sized derivatives still use the standard converter.

The generated resources include PNG, Windows ICO, macOS ICNS, and mobile icon
sizes. Mobile icon files do not imply Android/iOS implementation or a release.
Platform-required opaque icon backgrounds are handled by the standard tool.
`BRANDING_MANIFEST.json` records the exact source and each derivative hash.

`app-icon.svg` embeds the exact approved PNG for compatibility with the previous
source filename. It is a raster wrapper, not a vector recreation. A true vector
version is unavailable from the supplied artwork and has not been invented.

## Application Boundary

The existing in-window UI brand mark is hardcoded in frontend markup/CSS.
Replacing that markup with the new image is a separate parent-owned code edit.
This update changes assets only, not layout, palette, Rust/Cargo/helper/security
code, tunnel availability, or signing status. No commit/push is performed here.
