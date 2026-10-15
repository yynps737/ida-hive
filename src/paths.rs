use std::path::Path;

/// Rust canonical paths on Windows have a verbatim prefix that the worker's
/// MSVC CRT file APIs reject. Normalize both input and staged output paths.
pub fn worker_path(path: &Path) -> String {
    let path = path.to_string_lossy();
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = path.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        path.into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_paths_preserve_normal_names_and_strip_verbatim_prefixes() {
        for (input, expected) in [
            (r"\\?\C:\db\database.i64", r"C:\db\database.i64"),
            (r"\\?\UNC\server\share\database.i64", r"\\server\share\database.i64"),
            ("/tmp/we ird — 名字/database.i64", "/tmp/we ird — 名字/database.i64"),
        ] {
            assert_eq!(worker_path(Path::new(input)), expected);
        }
    }
}
