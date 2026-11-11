# Third-party notices

Velum UI, storage, migration and provisioning glue are separate from the VPN engines below. «Собственный продукт» не означает авторство протокола или стороннего dataplane.

| Component | Pinned source | License | Distribution note |
|---|---|---|---|
| AmneziaWG Go | `amnezia-vpn/amneziawg-go`, `v3.0.2`, commit `0527dfa47639714dd8f5c9ffbd9d40d19083f0ba` | MIT | Include upstream copyright/license with the binary. |
| AmneziaWG Windows library / helper reference | library `v3.0.2`, commit `575626d8f8aa5b64114cf378a08e54bf852d909b`; reference client commit `5cbc7dcb607e761975fdcc78bd616b58ab48f8a2` | MIT | Preserve upstream notices for linked code and adapted service lifecycle; see `windows-backend/THIRD_PARTY_NOTICES.md`. |
| Wintun prebuilt Windows DLL | official archive `0.14.1`, SHA-256 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` | archive-specific precompiled-binary license | Keep official signed DLL unchanged and ship its full archive license. The kernel source license is not the binary redistribution license. |
| AmneziaWG tools | `amnezia-vpn/amneziawg-tools`, `v3.0.20260730`, commit `d09ecc38425082e472368dd2bf8c4c42d10cae03` | GPL-2.0-only | Docker distribution must accompany the complete corresponding source/build scripts or a GPL-compliant written offer. |
| Tauri and Rust crates | versions locked by `Cargo.lock` | MIT, Apache-2.0 and compatible licenses | Generate SBOM/license report from the final release graph. |
| Lucide (including Feather-derived icons) | version locked by `app/pnpm-lock.yaml` | ISC plus retained MIT Feather notice | Preserve both upstream notices. |
| Vite/TypeScript | versions locked by `app/pnpm-lock.yaml` | MIT / Apache-2.0 | Build-only components still belong in the release SBOM where applicable. |
| Unbound | `1.26.0`, official tarball SHA-256 `77458a7156e275c0b7b17fabcb357cb12445d95cfcb26fb9bb7d5ecba45e0b63` | BSD-3-Clause | Include upstream license and corresponding pinned source tarball. |
| Debian runtime packages | Debian trixie package set in the image | Package-specific licenses | Preserve `/usr/share/doc/*/copyright` and publish an image SBOM. |

Official upstreams:

- https://github.com/amnezia-vpn/amneziawg-go
- https://github.com/amnezia-vpn/amneziawg-tools
- https://github.com/tauri-apps/tauri
- https://github.com/lucide-icons/lucide

This file is a release checklist, not a replacement for the complete license texts. A public Velum image/installer is not approved until the CI artifact contains those texts, the GPL source bundle and a signed SBOM/provenance statement.
