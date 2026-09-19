use crate::analysis::binary::file_regions;
use crate::analysis::{read_target, shannon_entropy, strings};
use crate::engine::runner::{absorb, run_command, tool_available};
use crate::engine::{Status, StepRequest, StepResult};
use goblin::Object;

const PACKER_SECTIONS: &[(&str, &str)] = &[
    ("UPX0", "UPX"),
    ("UPX1", "UPX"),
    ("UPX2", "UPX"),
    (".UPX", "UPX"),
    (".aspack", "ASPack"),
    (".adata", "ASPack"),
    (".ASPack", "ASPack"),
    (".themida", "Themida / WinLicense"),
    (".winlice", "Themida / WinLicense"),
    (".vmp0", "VMProtect"),
    (".vmp1", "VMProtect"),
    (".vmp2", "VMProtect"),
    (".petite", "Petite"),
    (".MPRESS1", "MPRESS"),
    (".MPRESS2", "MPRESS"),
    (".enigma1", "Enigma Protector"),
    (".enigma2", "Enigma Protector"),
    (".nsp0", "NsPack"),
    (".nsp1", "NsPack"),
    (".nsp2", "NsPack"),
    ("nsp0", "NsPack"),
    (".pec1", "PECompact"),
    ("PEC2", "PECompact"),
    ("pec", "PECompact"),
    (".boom", "The Boomerang List Builder"),
    (".RLPack", "RLPack"),
    (".Upack", "Upack"),
    (".ByDll", "Upack"),
    (".yP", "Y0da Protector"),
    (".y0da", "Y0da Protector"),
    (".mackt", "ImpRec-rebuilt import table"),
    (".perplex", "Perplex PE Protector"),
    (".neolit", "NeoLite"),
    (".sforce3", "StarForce"),
    (".taz", "PESpin"),
    (".winapi", "API Override"),
    ("kkrunchy", "kkrunchy"),
    (".mnbvcx1", "unknown packer (mnbvcx)"),
    (".shrink1", "Shrinker"),
    (".spack", "Simple Pack"),
    (".packed", "RLPack / generic"),
    (".dsstext", "DSS packer"),
    (".gentee", "Gentee installer"),
    ("PEPACK!!", "PE-PACK"),
    (".ccg", "CCG packer"),
    (".pklstb", "PKLite"),
    (".WWPACK", "WWPACK"),
    ("BitArts", "Crunch / BitArts"),
    ("DAStub", "DAStub Dragon Armor"),
    ("!EPack", "EPack"),
    (".ecode", "Easy Programming Language"),
    (".edata2", "Themida"),
    (".rmnet", "Ramnit infection"),
    (".text1", "possible virus/packer artifact"),
    (".nicode", "unknown packer"),
    (".Themida", "Themida"),
    (".tsuarch", "TSULoader"),
    (".tsustub", "TSULoader"),
    ("MEW", "MEW"),
    (".MaskPE", "MaskPE"),
    (".Alien", "Alienyze"),
    (".enigma", "Enigma"),
    ("ProCrypt", "ProCrypt"),
    (".seau", "SeauSFX"),
    (".sedata", "Safengine Shielden"),
    (".svkp", "SVKP"),
    (".exe_pack", "generic packer"),
    ("PELOCKnt", "PELock"),
    (".pelock", "PELock"),
    (".arma", "Armadillo"),
    (".securom", "SecuROM"),
    (".stab", "generic protector"),
];

const PACKER_STRINGS: &[(&str, &str)] = &[
    ("UPX!", "UPX"),
    (
        "$Info: This file is packed with the UPX executable packer",
        "UPX",
    ),
    ("ASPack", "ASPack"),
    ("Themida", "Themida"),
    ("WinLicense", "WinLicense"),
    ("VMProtect", "VMProtect"),
    ("MPRESS", "MPRESS"),
    ("PECompact2", "PECompact"),
    ("PEtite", "Petite"),
    ("Enigma protector", "Enigma Protector"),
    ("Armadillo", "Armadillo"),
    ("SecuROM", "SecuROM"),
    ("Obsidium", "Obsidium"),
    ("MoleBox", "MoleBox"),
    ("ExeStealth", "ExeStealth"),
    ("ConfuserEx", "ConfuserEx (.NET obfuscator)"),
    ("Confuser", "Confuser (.NET obfuscator)"),
    ("Eazfuscator", "Eazfuscator (.NET obfuscator)"),
    ("Dotfuscator", "Dotfuscator (.NET obfuscator)"),
    ("SmartAssembly", "SmartAssembly (.NET obfuscator)"),
    ("Babel Obfuscator", "Babel (.NET obfuscator)"),
    (".NETReactor", ".NET Reactor"),
    ("Agile.NET", "Agile.NET"),
    ("ILProtector", "ILProtector"),
    ("Crypto Obfuscator", "Crypto Obfuscator (.NET)"),
    ("PyArmor", "PyArmor"),
    ("pyarmor", "PyArmor"),
    ("vmp_", "VMProtect (marker)"),
    ("dUP2", "diablo2oo2's Universal Patcher"),
    ("MEW 11", "MEW"),
    ("FSG!", "FSG"),
    ("PEBundle", "PEBundle"),
    ("NsPack", "NsPack"),
    ("nSPack", "NsPack"),
    ("yoda's Crypter", "Yoda's Crypter"),
    ("Yoda's Protector", "Yoda's Protector"),
    ("EXECryptor", "EXECryptor"),
    ("tElock", "tElock"),
    ("PEShield", "PEShield"),
    ("ShellCore", "unknown"),
    ("Molebox", "MoleBox"),
    ("Exe Stealth", "ExeStealth"),
    ("KKrunchy", "kkrunchy"),
    ("Petite", "Petite"),
    ("NeoLite", "NeoLite"),
    ("Krypton", "Krypton"),
];

const TOOLCHAIN_STRINGS: &[(&str, &str)] = &[
    ("Go build ID:", "Go"),
    ("Go buildinf:", "Go"),
    ("go1.", "Go (version string present)"),
    ("runtime.gopanic", "Go"),
    ("rustc/", "Rust"),
    ("/rustc/", "Rust"),
    ("rust_begin_unwind", "Rust"),
    ("core::panicking", "Rust"),
    ("_MEIPASS", "PyInstaller (bundled Python)"),
    ("pyi-runtime-tmpdir", "PyInstaller"),
    ("PyInstaller", "PyInstaller"),
    ("Nuitka", "Nuitka (compiled Python)"),
    ("py2exe", "py2exe"),
    ("Py_Initialize", "embeds a Python interpreter"),
    ("Nullsoft Install System", "NSIS installer"),
    ("NullsoftInst", "NSIS installer"),
    ("Inno Setup", "Inno Setup installer"),
    ("InstallShield", "InstallShield installer"),
    ("WiX Toolset", "WiX / MSI"),
    ("AutoIt", "AutoIt script host"),
    ("AU3!", "AutoIt compiled script"),
    (
        "This program cannot be run in DOS mode",
        "PE (DOS stub present)",
    ),
    ("Microsoft (R) Optimizing Compiler", "MSVC"),
    ("MSVCR", "MSVC runtime"),
    ("VCRUNTIME", "MSVC runtime (2015+)"),
    ("api-ms-win-crt", "Universal CRT (MSVC 2015+)"),
    ("mingw", "MinGW"),
    ("MinGW", "MinGW"),
    ("GCC: (", "GCC"),
    ("clang version", "Clang"),
    ("Apple clang", "Apple Clang"),
    ("Borland", "Borland / Delphi"),
    ("Embarcadero", "Embarcadero Delphi"),
    ("Delphi", "Delphi"),
    ("FPC ", "Free Pascal"),
    ("Free Pascal", "Free Pascal"),
    ("mscoree.dll", ".NET (CLR loader)"),
    ("_CorExeMain", ".NET executable"),
    ("_CorDllMain", ".NET library"),
    ("v4.0.30319", ".NET Framework 4.x"),
    ("v2.0.50727", ".NET Framework 2.0/3.5"),
    ("hostfxr", ".NET Core / .NET 5+ apphost"),
    ("Electron", "Electron"),
    ("node_modules", "Node.js bundle"),
    ("NODE_OPTIONS", "Node.js (pkg / nexe bundle)"),
    ("Qt5Core", "Qt 5"),
    ("Qt6Core", "Qt 6"),
    ("libgtk", "GTK"),
    ("wxWidgets", "wxWidgets"),
    ("Unity", "Unity engine"),
    ("UnityPlayer", "Unity engine"),
    ("Mono", "Mono runtime"),
    ("Java/", "Java launcher"),
    ("jvm.dll", "Java (bundled JVM)"),
    ("libjvm", "Java (bundled JVM)"),
    ("golang", "Go"),
    ("Zig ", "Zig"),
    ("nim_", "Nim"),
    ("NimMain", "Nim"),
    ("Cython", "Cython"),
    ("sqlite3", "bundled SQLite"),
    ("OpenSSL", "bundled OpenSSL"),
    ("libcurl", "libcurl"),
    ("WinHttp", "WinHTTP"),
    ("PowerShell", "PowerShell usage"),
    ("cmd.exe", "cmd.exe usage"),
    ("wscript", "Windows Script Host"),
    ("mshta", "mshta usage"),
    ("regsvr32", "regsvr32 usage"),
    ("rundll32", "rundll32 usage"),
    ("Xamarin", "Xamarin"),
    ("Flutter", "Flutter"),
    ("CMake", "built with CMake"),
    ("cargo", "Rust (cargo)"),
    ("swift", "Swift"),
];

pub struct Finding {
    pub name: String,
    pub evidence: String,
}

// Lossy-decoding the file and using str::contains (SIMD) is far faster than
// windows() over raw bytes: ~150 signatures on a multi-MB sample.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    let text = String::from_utf8_lossy(haystack);
    text.contains(std::str::from_utf8(needle).unwrap_or(""))
}

pub fn signatures(data: &[u8]) -> Vec<Finding> {
    let mut out = Vec::new();
    if let Ok(regions) = file_regions(data) {
        for r in &regions {
            for (sig, name) in PACKER_SECTIONS {
                if r.name == *sig || (sig.len() > 3 && r.name.starts_with(sig)) {
                    out.push(Finding {
                        name: name.to_string(),
                        evidence: format!("section `{}`", r.name),
                    });
                }
            }
        }
    }
    let text = String::from_utf8_lossy(data);
    for (sig, name) in PACKER_STRINGS {
        if text.contains(sig) && !out.iter().any(|f| f.name == *name) {
            out.push(Finding {
                name: name.to_string(),
                evidence: format!("string \"{sig}\""),
            });
        }
    }
    out
}

pub fn toolchain(data: &[u8]) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    if let Ok(obj) = Object::parse(data) {
        match obj {
            Object::Elf(elf) => {
                for sh in &elf.section_headers {
                    let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
                    match name {
                        ".gopclntab" | ".go.buildinfo" | ".note.go.buildid" => out.push(Finding {
                            name: "Go".into(),
                            evidence: format!("section `{name}`"),
                        }),
                        ".comment" => {
                            let start = sh.sh_offset as usize;
                            let end = start.saturating_add(sh.sh_size as usize).min(data.len());
                            if start < end {
                                for s in strings::ascii(&data[start..end], 4) {
                                    out.push(Finding {
                                        name: s.clone(),
                                        evidence: "section `.comment`".into(),
                                    });
                                }
                            }
                        }
                        ".note.ABI-tag" => {}
                        _ => {}
                    }
                }
                if elf.interpreter.is_none() && elf.dynamic.is_none() {
                    out.push(Finding {
                        name: "statically linked".into(),
                        evidence: "no PT_INTERP / PT_DYNAMIC".into(),
                    });
                }
                if elf.libraries.iter().any(|l| l.starts_with("libstdc++")) {
                    out.push(Finding {
                        name: "C++ (libstdc++)".into(),
                        evidence: "NEEDED libstdc++".into(),
                    });
                }
            }
            Object::PE(pe) => {
                if let Some(opt) = &pe.header.optional_header
                    && opt.data_directories.get_clr_runtime_header().is_some()
                {
                    out.push(Finding {
                        name: ".NET assembly".into(),
                        evidence: "CLR runtime header data directory".into(),
                    });
                }
                if pe
                    .libraries
                    .iter()
                    .any(|l| l.eq_ignore_ascii_case("msvcrt.dll"))
                    && contains(data, b"mingw")
                {
                    out.push(Finding {
                        name: "MinGW".into(),
                        evidence: "msvcrt.dll + mingw strings".into(),
                    });
                }

                if contains(&data[..data.len().min(0x400)], b"Rich") {
                    out.push(Finding {
                        name: "MSVC (Rich header present)".into(),
                        evidence: "\"Rich\" marker in DOS stub".into(),
                    });
                }
                if pe
                    .sections
                    .iter()
                    .any(|s| s.name().unwrap_or("") == ".rustc")
                {
                    out.push(Finding {
                        name: "Rust".into(),
                        evidence: "section `.rustc`".into(),
                    });
                }
            }
            Object::Mach(_) => {
                if contains(data, b"__swift5_") {
                    out.push(Finding {
                        name: "Swift".into(),
                        evidence: "__swift5_* sections".into(),
                    });
                }
                if contains(data, b"__objc_") {
                    out.push(Finding {
                        name: "Objective-C".into(),
                        evidence: "__objc_* sections".into(),
                    });
                }
            }
            _ => {}
        }
    }
    let text = String::from_utf8_lossy(data);
    for (sig, name) in TOOLCHAIN_STRINGS {
        if text.contains(sig) && !out.iter().any(|f| f.name == *name) {
            out.push(Finding {
                name: name.to_string(),
                evidence: format!("string \"{sig}\""),
            });
        }
    }
    out
}

pub struct Heuristic {
    pub score: u8,
    pub text: String,
}

pub fn heuristics(data: &[u8]) -> Vec<Heuristic> {
    let mut out = Vec::new();
    let Ok(obj) = Object::parse(data) else {
        return out;
    };
    match obj {
        Object::PE(pe) => {
            let mut code_sections = 0;
            let mut entry_in_code = false;
            let mut last_end = 0usize;
            for s in &pe.sections {
                let name = s.name().unwrap_or("?").to_string();
                let c = s.characteristics;
                let (start, size) = (s.pointer_to_raw_data as usize, s.size_of_raw_data as usize);
                let end = start.saturating_add(size).min(data.len());
                last_end = last_end.max(end);
                let exec = c & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0;
                let write = c & goblin::pe::section_table::IMAGE_SCN_MEM_WRITE != 0;
                if exec {
                    code_sections += 1;
                }
                if exec && write {
                    out.push(Heuristic { score: 2, text: format!("section `{name}` is writable AND executable (self-modifying / unpacking stub)") });
                }
                if start < end {
                    let e = shannon_entropy(&data[start..end]);
                    if exec && e > 7.0 {
                        out.push(Heuristic { score: 3, text: format!("executable section `{name}` has entropy {e:.2} (compressed/encrypted code)") });
                    }
                }
                if s.virtual_size > 0
                    && size > 0
                    && s.virtual_size as usize > size * 4
                    && s.virtual_size > 0x10000
                {
                    out.push(Heuristic { score: 2, text: format!("section `{name}` is {}x larger in memory than on disk (room to unpack)", s.virtual_size as usize / size) });
                }
                if size == 0 && s.virtual_size > 0x1000 && exec {
                    out.push(Heuristic {
                        score: 3,
                        text: format!(
                            "executable section `{name}` is empty on disk but {} bytes in memory",
                            s.virtual_size
                        ),
                    });
                }
                let entry = pe.entry as usize;
                if entry >= s.virtual_address as usize
                    && entry < (s.virtual_address + s.virtual_size.max(s.size_of_raw_data)) as usize
                {
                    if exec {
                        entry_in_code = true;
                    }
                    if !matches!(name.as_str(), ".text" | "CODE" | ".code" | ".init" | "text") {
                        out.push(Heuristic {
                            score: 2,
                            text: format!(
                                "entry point 0x{entry:x} is in section `{name}`, not in .text"
                            ),
                        });
                    }
                }
            }
            if !entry_in_code && !pe.sections.is_empty() {
                out.push(Heuristic {
                    score: 2,
                    text: "entry point is outside every executable section".into(),
                });
            }
            if code_sections == 0 {
                out.push(Heuristic {
                    score: 1,
                    text: "no executable section at all".into(),
                });
            }
            let imports = pe.imports.len();
            if imports > 0 && imports < 8 {
                let names: Vec<&str> = pe.imports.iter().map(|i| i.name.as_ref()).collect();
                let loader = names.iter().any(|n| n.starts_with("LoadLibrary"))
                    && names.iter().any(|n| n.starts_with("GetProcAddress"));
                out.push(Heuristic {
                    score: if loader { 3 } else { 1 },
                    text: format!(
                        "only {imports} import(s){}: {}",
                        if loader {
                            " including LoadLibrary+GetProcAddress (dynamic API resolution)"
                        } else {
                            ""
                        },
                        names.join(", ")
                    ),
                });
            } else if imports == 0 {
                out.push(Heuristic {
                    score: 2,
                    text: "empty import table".into(),
                });
            }
            if data.len() > last_end + 512 {
                let overlay = &data[last_end..];
                let e = shannon_entropy(overlay);
                out.push(Heuristic {
                    score: if e > 7.0 { 2 } else { 1 },
                    text: format!(
                        "overlay: {} bytes appended after the last section (entropy {e:.2}){}",
                        overlay.len(),
                        if e > 7.0 {
                            ", likely an encrypted payload or installer data"
                        } else {
                            ""
                        }
                    ),
                });
            }
        }
        Object::Elf(elf) => {
            let mut has_sections = !elf.section_headers.is_empty();
            if elf.section_headers.len() <= 1 {
                has_sections = false;
                out.push(Heuristic {
                    score: 2,
                    text: "no section headers (stripped by a packer or built without them)".into(),
                });
            }
            for ph in &elf.program_headers {
                use goblin::elf::program_header::{PF_W, PF_X, PT_LOAD};
                if ph.p_type == PT_LOAD && ph.p_flags & PF_X != 0 {
                    if ph.p_flags & PF_W != 0 {
                        out.push(Heuristic {
                            score: 2,
                            text: format!(
                                "PT_LOAD segment at 0x{:x} is writable AND executable",
                                ph.p_vaddr
                            ),
                        });
                    }
                    let start = ph.p_offset as usize;
                    let end = start.saturating_add(ph.p_filesz as usize).min(data.len());
                    if start < end {
                        let e = shannon_entropy(&data[start..end]);
                        if e > 7.0 {
                            out.push(Heuristic {
                                score: 3,
                                text: format!(
                                    "executable segment at 0x{:x} has entropy {e:.2}",
                                    ph.p_vaddr
                                ),
                            });
                        }
                    }
                    if ph.p_memsz > ph.p_filesz * 4 && ph.p_memsz > 0x10000 {
                        out.push(Heuristic {
                            score: 1,
                            text: format!(
                                "executable segment at 0x{:x} grows {}x in memory",
                                ph.p_vaddr,
                                ph.p_memsz / ph.p_filesz.max(1)
                            ),
                        });
                    }
                }
            }
            if has_sections {
                let imports = elf.dynsyms.iter().filter(|s| s.is_import()).count();
                if elf.dynamic.is_some() && imports < 5 {
                    out.push(Heuristic {
                        score: 2,
                        text: format!("dynamically linked but only {imports} imported symbol(s)"),
                    });
                }
            }
            if elf.section_headers.is_empty() && elf.dynamic.is_none() {
                out.push(Heuristic {
                    score: 1,
                    text: "static binary with no section headers: typical of UPX-packed ELF".into(),
                });
            }
        }
        _ => {}
    }
    let overall = shannon_entropy(data);
    if overall > 7.2 {
        out.push(Heuristic {
            score: 2,
            text: format!("whole-file entropy {overall:.2}: mostly compressed or encrypted"),
        });
    }
    out
}

pub fn run(req: &StepRequest) -> StepResult {
    let mut result = StepResult::new(req.step);
    let data = match read_target(&req.target) {
        Ok(d) => d,
        Err(e) => return StepResult::failed(req.step, e),
    };
    let none = !req.any_checked();

    if none || req.is_checked(0) {
        let sigs = signatures(&data);
        result.push_line(format!("== Packer signatures ({}) ==", sigs.len()));
        if sigs.is_empty() {
            result.push_line("  no known packer signature");
        }
        for f in &sigs {
            result.push_line(format!("  {:<28} {}", f.name, f.evidence));
        }
        result.push_line("");
    }

    if none || req.is_checked(1) {
        let tc = toolchain(&data);
        result.push_line(format!("== Compiler / toolchain ({}) ==", tc.len()));
        if tc.is_empty() {
            result.push_line("  no recognizable toolchain marker (stripped, or packed)");
        }
        for f in &tc {
            result.push_line(format!("  {:<40} {}", f.name, f.evidence));
        }
        result.push_line("");
    }

    if none || req.is_checked(2) {
        let hs = heuristics(&data);
        let score: u32 = hs.iter().map(|h| h.score as u32).sum();
        result.push_line(format!("== Packing heuristics (score {score}) =="));
        if hs.is_empty() {
            result.push_line("  nothing unusual");
        }
        for h in &hs {
            result.push_line(format!("  [{}] {}", "+".repeat(h.score as usize), h.text));
        }
        result.push_line(match score {
            0..=1 => "  verdict: probably not packed",
            2..=4 => "  verdict: some signs of packing or obfuscation, worth a closer look",
            _ => "  verdict: very likely packed or protected",
        });
        result.push_line("");
    }

    if req.is_checked(3) {
        if !tool_available("upx") {
            result.push_line("[upx] not installed: cannot unpack (see doctor, `i`)");
        } else {
            let out = req.target.with_extension(format!(
                "{}unpacked",
                req.target
                    .extension()
                    .map(|e| format!("{}.", e.to_string_lossy()))
                    .unwrap_or_default()
            ));
            let args = vec![
                "-d".to_string(),
                "-o".to_string(),
                out.to_string_lossy().into_owned(),
                req.target.to_string_lossy().into_owned(),
            ];
            if !crate::engine::runner::dry_run() {
                let _ = std::fs::remove_file(&out);
            }
            let ok = absorb(&mut result, run_command("upx", &args));
            if ok && out.is_file() {
                result.push_line(format!(
                    "unpacked file written: {} (pick it with @ to analyze it)",
                    out.display()
                ));
            } else {
                result.status = Status::Ok;
                result.push_line(
                    "upx could not unpack this file (not UPX-packed, or a modified UPX)",
                );
            }
        }
    }
    result
}
