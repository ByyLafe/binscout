use crate::engine::runner::{absorb, run_command, tool_available};
use crate::engine::{StepRequest, StepResult};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Zip,
    Tar,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
    SevenZip,
    Rar,
    Deb,
    Rpm,
    Cab,
    Iso,
    Msi,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Zip => "zip (also jar/apk/docx/xlsx/pptx/ipa)",
            Self::Tar => "tar",
            Self::Gzip => "gzip",
            Self::Bzip2 => "bzip2",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
            Self::SevenZip => "7-zip",
            Self::Rar => "rar",
            Self::Deb => "Debian package (ar)",
            Self::Rpm => "RPM package",
            Self::Cab => "Microsoft cabinet",
            Self::Iso => "ISO 9660 image",
            Self::Msi => "MSI / OLE compound document",
        }
    }
}

pub fn detect(data: &[u8]) -> Option<Kind> {
    let starts = |m: &[u8]| data.starts_with(m);
    if starts(b"PK\x03\x04") || starts(b"PK\x05\x06") {
        return Some(Kind::Zip);
    }
    if starts(b"\x1f\x8b") {
        return Some(Kind::Gzip);
    }
    if starts(b"BZh") {
        return Some(Kind::Bzip2);
    }
    if starts(b"\xfd7zXZ\x00") {
        return Some(Kind::Xz);
    }
    if starts(b"\x28\xb5\x2f\xfd") {
        return Some(Kind::Zstd);
    }
    if starts(b"7z\xbc\xaf\x27\x1c") {
        return Some(Kind::SevenZip);
    }
    if starts(b"Rar!\x1a\x07") {
        return Some(Kind::Rar);
    }
    if starts(b"!<arch>\n") {
        return Some(
            if data.windows(12).take(200).any(|w| w == b"debian-binar") {
                Kind::Deb
            } else {
                Kind::Tar
            },
        );
    }
    if starts(b"\xed\xab\xee\xdb") {
        return Some(Kind::Rpm);
    }
    if starts(b"MSCF") {
        return Some(Kind::Cab);
    }
    if starts(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
        return Some(Kind::Msi);
    }
    if data.len() > 0x8006 && &data[0x8001..0x8006] == b"CD001" {
        return Some(Kind::Iso);
    }
    if data.len() > 0x106 && &data[0x101..0x106] == b"ustar" {
        return Some(Kind::Tar);
    }
    None
}

pub fn extraction_dir(target: &Path) -> PathBuf {
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    PathBuf::from(format!("_{name}.container"))
}

fn commands(kind: Kind) -> Vec<(&'static str, Vec<&'static str>, Vec<&'static str>)> {
    match kind {
        Kind::Zip => vec![
            (
                "unzip",
                vec!["-l", "{f}"],
                vec!["-o", "-q", "{f}", "-d", "{out}"],
            ),
            ("7z", vec!["l", "{f}"], vec!["x", "-y", "-o{out}", "{f}"]),
            (
                "bsdtar",
                vec!["-tvf", "{f}"],
                vec!["-xf", "{f}", "-C", "{out}"],
            ),
        ],
        Kind::Tar => vec![
            (
                "tar",
                vec!["-tvf", "{f}"],
                vec!["-xf", "{f}", "-C", "{out}"],
            ),
            ("7z", vec!["l", "{f}"], vec!["x", "-y", "-o{out}", "{f}"]),
        ],
        Kind::Gzip | Kind::Bzip2 | Kind::Xz | Kind::Zstd => vec![
            (
                "tar",
                vec!["-tvf", "{f}"],
                vec!["-xf", "{f}", "-C", "{out}"],
            ),
            ("7z", vec!["l", "{f}"], vec!["x", "-y", "-o{out}", "{f}"]),
        ],
        Kind::SevenZip | Kind::Cab | Kind::Iso | Kind::Msi | Kind::Rpm => vec![
            ("7z", vec!["l", "{f}"], vec!["x", "-y", "-o{out}", "{f}"]),
            (
                "bsdtar",
                vec!["-tvf", "{f}"],
                vec!["-xf", "{f}", "-C", "{out}"],
            ),
        ],
        Kind::Rar => vec![
            ("unrar", vec!["l", "{f}"], vec!["x", "-y", "{f}", "{out}/"]),
            ("7z", vec!["l", "{f}"], vec!["x", "-y", "-o{out}", "{f}"]),
        ],
        Kind::Deb => vec![
            ("dpkg-deb", vec!["-c", "{f}"], vec!["-x", "{f}", "{out}"]),
            ("7z", vec!["l", "{f}"], vec!["x", "-y", "-o{out}", "{f}"]),
            (
                "ar",
                vec!["-tv", "{f}"],
                vec!["-x", "--output={out}", "{f}"],
            ),
        ],
    }
}

fn fill(args: &[&str], target: &Path, out: &Path) -> Vec<String> {
    args.iter()
        .map(|a| {
            a.replace("{f}", &target.to_string_lossy())
                .replace("{out}", &out.to_string_lossy())
        })
        .collect()
}

pub fn run(req: &StepRequest) -> StepResult {
    let mut result = StepResult::new(req.step);
    let data = match crate::analysis::read_target(&req.target) {
        Ok(d) => d,
        Err(e) => return StepResult::failed(req.step, e),
    };
    let Some(kind) = detect(&data) else {
        return StepResult::skipped(
            req.step,
            "not an archive or container (no zip/tar/gzip/7z/rar/deb/rpm/cab/iso/msi magic)",
        );
    };
    result.push_line(format!("container: {}", kind.name()));
    let candidates = commands(kind);
    let Some((tool, list_args, extract_args)) =
        candidates.iter().find(|(t, _, _)| tool_available(t))
    else {
        let names: Vec<&str> = candidates.iter().map(|(t, _, _)| *t).collect();
        return StepResult::skipped(
            req.step,
            format!("{}: none of {} is installed", kind.name(), names.join(", ")),
        );
    };
    let out_dir = extraction_dir(&req.target);
    let none = !req.any_checked();

    if none || req.is_checked(0) {
        result.push_line("");
        absorb(
            &mut result,
            run_command(tool, &fill(list_args, &req.target, &out_dir)),
        );
    }

    if req.is_checked(1) {
        let created = if crate::engine::runner::dry_run() {
            Ok(())
        } else {
            std::fs::create_dir_all(&out_dir)
        };
        if let Err(e) = created {
            result.push_line(format!("cannot create {}: {e}", out_dir.display()));
            result.status = crate::engine::Status::Failed;
            return result;
        }
        let ok = absorb(
            &mut result,
            run_command(tool, &fill(extract_args, &req.target, &out_dir)),
        );
        if ok {
            let count = walkdir::WalkDir::new(&out_dir)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|e| e.file_type().is_file())
                .count();
            result.push_line(format!(
                "{count} file(s) extracted to {}: press @ and type its name to analyze one",
                out_dir.display()
            ));
        }
    }
    result
}
