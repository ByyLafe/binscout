use crate::analysis::binary::{anti, packer};
use crate::analysis::{container, hashes, human_size, shannon_entropy};
use goblin::Object;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Row {
    pub path: PathBuf,
    pub size: u64,
    pub kind: String,
    pub sha256: String,
    pub entropy: f64,
    pub packer: String,
    pub anti: usize,
    pub online: Option<String>,
}

pub fn kind_of(data: &[u8]) -> String {
    match Object::parse(data) {
        Ok(Object::Elf(elf)) => format!(
            "ELF{} {} {}",
            if elf.is_64 { 64 } else { 32 },
            goblin::elf::header::machine_to_str(elf.header.e_machine),
            goblin::elf::header::et_to_str(elf.header.e_type)
                .trim_start_matches("ET_")
                .to_lowercase()
        ),
        Ok(Object::PE(pe)) => format!(
            "PE{} {}{}",
            if pe.is_64 { "32+" } else { "32" },
            goblin::pe::header::machine_to_str(pe.header.coff_header.machine),
            if pe.is_lib { " dll" } else { "" }
        ),
        Ok(Object::Mach(_)) => "Mach-O".to_string(),
        Ok(Object::Archive(_)) => "ar archive".to_string(),
        _ => match container::detect(data) {
            Some(k) => k.name().split(' ').next().unwrap_or("archive").to_string(),
            None => {
                if data.starts_with(b"#!") {
                    "script".to_string()
                } else if data.starts_with(b"%PDF") {
                    "pdf".to_string()
                } else if data.iter().take(512).all(|b| b.is_ascii()) {
                    "text".to_string()
                } else {
                    "data".to_string()
                }
            }
        },
    }
}

pub fn analyze(path: &Path, online: bool) -> Option<Row> {
    let data = std::fs::read(path).ok()?;
    let sha256 = hashes::sha256_hex(&data);
    let sigs = packer::signatures(&data);
    let heur: u32 = packer::heuristics(&data)
        .iter()
        .map(|h| h.score as u32)
        .sum();
    let packer = if let Some(f) = sigs.first() {
        f.name.clone()
    } else if heur >= 5 {
        format!("likely (score {heur})")
    } else if heur >= 2 {
        format!("maybe ({heur})")
    } else {
        "-".to_string()
    };
    let anti = anti::scan(&data)
        .iter()
        .filter(|h| !h.why.contains("weak signal"))
        .count();
    let online = if online {
        Some(match hashes::malwarebazaar(&sha256) {
            Ok(lines) => lines
                .first()
                .cloned()
                .unwrap_or_default()
                .replace("MalwareBazaar: ", ""),
            Err(e) => format!("error: {e}"),
        })
    } else {
        None
    };
    Some(Row {
        path: path.to_path_buf(),
        size: data.len() as u64,
        kind: kind_of(&data),
        sha256,
        entropy: shannon_entropy(&data),
        packer,
        anti,
        online,
    })
}

pub fn scan(dir: &Path, online: bool, max_files: usize) -> Vec<Row> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.is_file())
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    let mut rows: Vec<Row> = files
        .iter()
        .take(max_files)
        .filter_map(|p| analyze(p, online))
        .collect();
    // Executables first, then archives and scripts, then data: what an analyst opens first.
    rows.sort_by_key(|r| {
        let rank = if r.kind.starts_with("ELF")
            || r.kind.starts_with("PE")
            || r.kind.starts_with("Mach")
        {
            0
        } else if r.kind == "script"
            || r.kind == "zip"
            || r.kind.contains("archive")
            || r.kind == "7-zip"
            || r.kind == "rar"
        {
            1
        } else {
            2
        };
        (rank, std::cmp::Reverse(r.anti), r.path.clone())
    });
    rows
}

pub fn table(rows: &[Row]) -> String {
    let mut out = String::new();
    let has_online = rows.iter().any(|r| r.online.is_some());
    out.push_str(&format!(
        "{:<32} {:>9} {:<22} {:>7} {:<22} {:>4} {:<16}{}\n",
        "file",
        "size",
        "type",
        "entropy",
        "packer",
        "anti",
        "sha256",
        if has_online { " bazaar" } else { "" }
    ));
    for r in rows {
        let name: String = r
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
            .chars()
            .take(32)
            .collect();
        let packer: String = r.packer.chars().take(22).collect();
        out.push_str(&format!(
            "{:<32} {:>9} {:<22} {:>7.3} {:<22} {:>4} {}{}\n",
            name,
            human_size(r.size),
            r.kind.chars().take(22).collect::<String>(),
            r.entropy,
            packer,
            r.anti,
            &r.sha256[..16],
            r.online
                .as_ref()
                .map(|o| format!(" {o}"))
                .unwrap_or_default()
        ));
    }
    out.push_str(&format!("{} file(s)\n", rows.len()));
    out
}
