#[cfg(windows)]
pub mod windows;

#[cfg(windows)]
pub use windows::{install_service, run_dispatcher, uninstall_service};
