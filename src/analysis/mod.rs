pub mod binary;
pub mod compare;
pub mod container;
pub mod disasm;
pub mod hashes;
pub mod iocs;
pub mod parsers;
pub mod strings;

use std::path::Path;

pub fn read_target(path: &Path) -> Result<Vec<u8>, String> {
    // A preview only needs headers (format, entry point); reading 64 KiB keeps it instant
    // on every keystroke even for large samples.
    if crate::engine::runner::dry_run() {
        use std::io::Read;
        let mut f = std::fs::File::open(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let mut buf = vec![0u8; 64 * 1024];
        let n = f
            .read(&mut buf)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        buf.truncate(n);
        return Ok(buf);
    }
    std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in data {
        counts[*b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[unit])
    }
}
