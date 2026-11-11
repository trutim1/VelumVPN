fn main() {
    // The standalone preview embeds Vite's output. Rebuild on frontend-only
    // changes as well; an incremental Rust build must not ship stale assets.
    println!("cargo:rerun-if-changed=../dist");
    tauri_build::build()
}
