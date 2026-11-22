# SeaORM 2.0.4 manifest patch

This copy contains the crates.io release's library sources and licenses. The manifest drops the weak Serde feature on Chrono and the weak Time feature on Arrow. Cargo resolves these unused dependencies into the lockfile ([cargo#10801](https://github.com/rust-lang/cargo/issues/10801)), where RustSec reports the Chrono advisory. This project enables neither Chrono nor Arrow. The SQLite driver import uses the same feature gate as its only consumer, so the vendored build remains warning-free.

When updating SeaORM, check whether the registry release resolves without Chrono and remove this patch when it does.
