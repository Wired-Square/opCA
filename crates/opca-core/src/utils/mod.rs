pub mod datetime;
pub mod files;

/// Run an async future on the current tokio runtime (if one exists) or
/// create a temporary one.  This avoids panicking when called from inside
/// a Tauri async command handler.
pub(crate) fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        // We are already inside a tokio runtime (e.g. Tauri).
        // Use block_in_place so we don't block an async worker.
        tokio::task::block_in_place(|| handle.block_on(fut))
    } else {
        // No runtime — create a lightweight one.
        tokio::runtime::Runtime::new()
            .expect("failed to create tokio runtime")
            .block_on(fut)
    }
}
