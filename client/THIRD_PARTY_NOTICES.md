# Third-party components

Original Velum code is GPL-3.0-only by owner authorization. Third-party code keeps its own license.

Client: Tauri/Rust and frontend dependencies are locked under client/. Some indirect crates are MPL-2.0;
binary distribution must retain notices and tell recipients where to obtain their exact covered sources.
A Windows legacy-binary audit and covered source bundle are prepared separately; do not treat the original checklist as all license texts.

Server build recipe pins AmneziaWG Go (MIT), AmneziaWG tools (GPL-2.0-only) and Unbound (BSD-3-Clause).
These are separate upstream programs, not original Velum protocols. The Dockerfile retains licenses and source archives.
For distributed images verify complete corresponding source/build materials and Debian/package notices; do not infer compliance from a Dockerfile alone.

Lucide is ISC with retained Feather MIT portions. Microsoft WebView2 loader/SDK terms must also be retained as applicable;
the separately installed WebView2 Runtime is not included here. This source export does not vendor third-party dependencies.

The original project notice is preserved verbatim in docs/ORIGINAL_THIRD_PARTY_NOTICES.md as historical scope,
not a change to any upstream license and not a claim all listed components ship with the GUI.
