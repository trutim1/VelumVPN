# Velum VPN

<img src="client/app/public/assets/velum-logo-512-20261112.png" alt="Velum logo" width="96" height="96">

Открытые исходники клиента и отдельной серверной реализации Velum.
Репозиторий: [trutim1/VelumVPN](https://github.com/trutim1/VelumVPN).
Новости: [ComputerHelper](https://t.me/+BkWng1uIFj9hZTZi).
Публичный контакт: **anon12anonov@gmail.com**.

Логотип в исходниках обновлён для будущих сборок; ранее опубликованные Preview
бинарники и архивы не перезаписываются. / Source branding is updated for future
builds; published Preview binaries and archives remain unchanged.

## Статус / Status

Это предварительная разработка, не Stable VPN. Windows GUI импортирует
AWG/WireGuard `.conf` и connection-only Amnezia `.vpn`, хранит профили через
DPAPI, но **не запускает VPN-туннель**. Каталог протоколов не обещает рабочие
адаптеры. Per-app rules пока черновик. Kill switch и отсутствие DNS/IPv6-утечек
этой поставкой не подтверждены. Не отключайте средства защиты ради запуска.

This is a pre-release project, not a production VPN. The Windows GUI supports
native profile import and DPAPI storage but **does not establish a VPN tunnel**.
The protocol catalog and application rules are not evidence of working adapters
or traffic protection. Linux capabilities are separately constrained; do not
infer Windows-native features on Linux. macOS/mobile releases are not provided.

## Дерево / Layout

- `client/`: Rust core, Tauri GUI, frontend sources, lockfiles and unit tests.
- `server/`: generic container build recipe, isolated-namespace entrypoint,
  peer transaction source and synthetic tests; no production deployment/profiles.
- `CONTRIBUTING.md`: fork/PR workflow; public read access, no direct push required.
- `SECURITY.md`: limitations and private reporting process.
- `SOURCE_SNAPSHOT.json`: initial export hashes and deliberate transformations.
  Later changes are recorded in Git; icon source/derivatives have their own
  `client/app/src-tauri/icons/BRANDING_MANIFEST.json`.

Серверные source defaults не являются настройками действующего VPS. Нельзя
запускать их поверх существующего VPN без собственной изолированной лаборатории,
проверки адресов/портов/namespace и отдельного разрешения владельца системы.
No production configuration, payment/site code, private deployment scripts,
peer/account data, credentials, Windows helper, driver, or old binaries is shipped.

## Сборка клиента / Client Build

Требуются Rust edition 2024, Node.js/pnpm и системные зависимости Tauri для вашей
ОС. Lockfiles фиксируют зависимости; toolchain/OS версии и build environment
должны отдельно фиксироваться в новых release manifests.

```text
cd client
cargo test --locked --all-targets
cd app
pnpm install --frozen-lockfile
pnpm test:ui
pnpm build
cargo test --locked --manifest-path src-tauri/Cargo.toml --all-targets
pnpm tauri build --no-bundle -- --locked
```

These commands build/test source; they do not install a privileged VPN service
or prove network isolation. Review dependency/build-script changes before
executing an untrusted branch. Do not use real VPN profiles for PR testing.

## Сервер / Server

`server/gateway/Dockerfile` builds separately pinned AmneziaWG Go, AWG tools and
Unbound. It is source material, not a ready-to-run production deployment.
Its build context is `server/`. `unbound.example.conf` contains generic defaults,
not private runtime configuration. Peer add/revoke implementation and four test
scripts are included as source, not connected to any live host. Never execute
peer-management code on a production system without a separate deployment review.
Operational compose/deploy/upgrade scripts and runtime profiles are excluded.

## Релизы / Releases

Новый исходный снимок нельзя объявлять исходниками старого Windows EXE.
The existing unsigned GUI executable is a **legacy preview of unverified source
provenance**. It is not claimed to match this tree or a new Git commit.
Release assets must state source commit, platform constraints, license notices,
checksums and build evidence. New binaries should be built from a clean reviewed
commit. No source tag is a reproducibility claim by itself.

README.ru.txt обязателен для скачиваемых пакетов. SHA-256 checks integrity, not
publisher identity or security. Do not bypass antivirus/SmartScreen/signatures.
Для рабочего доступа используйте отдельный совместимый
[официальный AmneziaVPN](https://amnezia.org/downloads), а не данный GUI Preview.
Velum is independent; it does not claim authorship of AmneziaWG or affiliation
with Amnezia, WireGuard, Tauri, Microsoft or their trademark owners.

## Лицензии / Licenses

Original Velum code in this source export: **GPL-3.0-only**, authorized by its
owner. See `LICENSE` and `COPYRIGHT.md`. Contribution of new original code is
under the same license. Third-party notices and grants remain unchanged.

AmneziaWG Go is MIT; AWG tools is GPL-2.0-only and is a separate program in the
server image, not GPL-2 code relicensed as GPL-3. Distributed server images must
provide its corresponding source and build materials under its original terms.
MPL-2.0 client dependencies retain file-level source obligations, including
notice of how to obtain the exact covered sources. See `THIRD_PARTY_NOTICES.md`.
No trademark license or endorsement is granted by the source-code license.
