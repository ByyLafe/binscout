use crate::analysis::read_target;
use crate::engine::{StepRequest, StepResult};
use goblin::Object;
use goblin::elf::{self, Elf};
use goblin::pe::PE;
use goblin::pe::dll_characteristic::*;

const DANGEROUS: &[(&str, &str)] = &[
    ("gets", "no bounds check, always overflowable"),
    ("strcpy", "no bounds check"),
    ("strcat", "no bounds check"),
    ("sprintf", "no bounds check"),
    ("vsprintf", "no bounds check"),
    ("scanf", "%s without width overflows"),
    ("sscanf", "%s without width overflows"),
    ("fscanf", "%s without width overflows"),
    ("stpcpy", "no bounds check"),
    ("wcscpy", "no bounds check"),
    ("wcscat", "no bounds check"),
    ("strncpy", "does not NUL-terminate on truncation"),
    ("strtok", "not reentrant, modifies its input"),
    ("realpath", "buffer must be PATH_MAX"),
    ("getwd", "deprecated, overflowable"),
    ("mktemp", "race condition, use mkstemp"),
    ("tmpnam", "race condition"),
    ("tempnam", "race condition"),
    ("system", "shell injection"),
    ("popen", "shell injection"),
    ("execl", "check argument sources"),
    ("execlp", "check argument sources"),
    ("execv", "check argument sources"),
    ("execvp", "check argument sources"),
    ("execve", "check argument sources"),
    ("memcpy", "check length computation"),
    ("alloca", "stack exhaustion / overflow"),
    ("rand", "not cryptographically secure"),
    ("srand", "not cryptographically secure"),
    ("WinExec", "shell/command execution"),
    ("ShellExecuteA", "shell/command execution"),
    ("ShellExecuteW", "shell/command execution"),
    ("CreateProcessA", "process creation"),
    ("CreateProcessW", "process creation"),
    ("CreateRemoteThread", "process injection primitive"),
    ("WriteProcessMemory", "process injection primitive"),
    ("VirtualAllocEx", "process injection primitive"),
    ("SetWindowsHookExA", "hooking / keylogging"),
    ("SetWindowsHookExW", "hooking / keylogging"),
    ("IsDebuggerPresent", "anti-debugging"),
    ("URLDownloadToFileA", "downloader behaviour"),
    ("URLDownloadToFileW", "downloader behaviour"),
    ("lstrcpyA", "no bounds check"),
    ("lstrcpyW", "no bounds check"),
    ("lstrcatA", "no bounds check"),
    ("lstrcatW", "no bounds check"),
    ("wsprintfA", "no bounds check"),
    ("wsprintfW", "no bounds check"),
];

struct Check {
    name: &'static str,
    enabled: Option<bool>,
    detail: String,
}

impl Check {
    fn line(&self) -> String {
        let state = match self.enabled {
            Some(true) => "[ OK ]",
            Some(false) => "[FAIL]",
            None => "[ ?? ]",
        };
        format!("{state} {:<14} {}", self.name, self.detail)
    }
}

struct Opts {
    nx: bool,
    pie: bool,
    relro: bool,
    canary: bool,
    fortify: bool,
    dangerous: bool,
}

pub fn run(req: &StepRequest) -> StepResult {
    let mut result = StepResult::new(req.step);
    let data = match read_target(&req.target) {
        Ok(d) => d,
        Err(e) => return StepResult::failed(req.step, e),
    };
    let none = !req.any_checked();
    let o = Opts {
        nx: none || req.is_checked(0),
        pie: none || req.is_checked(1),
        relro: none || req.is_checked(2),
        canary: none || req.is_checked(3),
        fortify: none || req.is_checked(4),
        dangerous: none || req.is_checked(5),
    };

    let (checks, imports) = match Object::parse(&data) {
        Ok(Object::Elf(elf)) => check_elf(&elf, &o),
        Ok(Object::PE(pe)) => check_pe(&pe, &o),
        Ok(_) => {
            return StepResult::failed(req.step, "mitigation checks support ELF and PE files only");
        }
        Err(e) => return StepResult::failed(req.step, format!("not a parseable executable: {e}")),
    };

    for c in &checks {
        result.push_line(c.line());
    }
    let enabled = checks.iter().filter(|c| c.enabled == Some(true)).count();
    let known = checks.iter().filter(|c| c.enabled.is_some()).count();
    if known > 0 {
        result.push_line(format!("\n{enabled}/{known} mitigations enabled"));
    }

    if o.dangerous {
        result.push_line("");
        let mut hits: Vec<(&str, &str)> = DANGEROUS
            .iter()
            .filter(|(f, _)| imports.iter().any(|i| i == f))
            .copied()
            .collect();
        hits.sort();
        if hits.is_empty() {
            result.push_line(format!(
                "no dangerous function among {} import(s)",
                imports.len()
            ));
        } else {
            result.push_line(format!("{} dangerous function(s) imported:", hits.len()));
            for (f, why) in hits {
                result.push_line(format!("  {f:<22} {why}"));
            }
        }
    }
    result
}

fn elf_imports(elf: &Elf) -> Vec<String> {
    let mut v: Vec<String> = elf
        .dynsyms
        .iter()
        .filter(|s| s.is_import())
        .filter_map(|s| elf.dynstrtab.get_at(s.st_name))
        .filter(|n| !n.is_empty())
        .map(|n| n.split('@').next().unwrap_or(n).to_string())
        .collect();
    v.sort();
    v.dedup();
    v
}

fn check_elf(elf: &Elf, o: &Opts) -> (Vec<Check>, Vec<String>) {
    use elf::dynamic::{DF_1_NOW, DF_BIND_NOW, DT_BIND_NOW, DT_FLAGS, DT_FLAGS_1};
    use elf::program_header::{PF_X, PT_GNU_RELRO, PT_GNU_STACK};
    let imports = elf_imports(elf);
    let mut checks = Vec::new();

    if o.nx {
        let stack = elf
            .program_headers
            .iter()
            .find(|p| p.p_type == PT_GNU_STACK);
        let (enabled, detail) = match stack {
            Some(p) if p.p_flags & PF_X == 0 => {
                (true, "stack is non-executable (PT_GNU_STACK without X)")
            }
            Some(_) => (false, "PT_GNU_STACK is executable"),
            None => (false, "no PT_GNU_STACK: kernel may map an executable stack"),
        };
        checks.push(Check {
            name: "NX",
            enabled: Some(enabled),
            detail: detail.into(),
        });
    }

    if o.pie {
        let (enabled, detail) = match elf.header.e_type {
            elf::header::ET_DYN if elf.interpreter.is_some() || elf.soname.is_none() => {
                (true, "position independent (ET_DYN)")
            }
            elf::header::ET_DYN => (true, "shared object (ET_DYN)"),
            elf::header::ET_EXEC => (false, "fixed load address (ET_EXEC)"),
            _ => (false, "not an executable"),
        };
        checks.push(Check {
            name: "PIE",
            enabled: Some(enabled),
            detail: detail.into(),
        });
    }

    if o.relro {
        let has_relro = elf.program_headers.iter().any(|p| p.p_type == PT_GNU_RELRO);
        let bind_now = elf.dynamic.as_ref().is_some_and(|d| {
            d.dyns.iter().any(|dy| {
                dy.d_tag == DT_BIND_NOW
                    || (dy.d_tag == DT_FLAGS && dy.d_val & DF_BIND_NOW != 0)
                    || (dy.d_tag == DT_FLAGS_1 && dy.d_val & DF_1_NOW != 0)
            })
        });
        let (enabled, detail) = match (has_relro, bind_now) {
            (true, true) => (Some(true), "full (GOT is read-only after load)"),
            (true, false) => (Some(false), "partial (GOT.PLT stays writable)"),
            (false, _) => (Some(false), "no RELRO"),
        };
        checks.push(Check {
            name: "RELRO",
            enabled,
            detail: detail.into(),
        });
    }

    if o.canary {
        let found = imports
            .iter()
            .any(|i| i == "__stack_chk_fail" || i == "__stack_chk_guard")
            || elf
                .syms
                .iter()
                .any(|s| elf.strtab.get_at(s.st_name) == Some("__stack_chk_fail"));
        let detail = if found {
            "__stack_chk_fail referenced"
        } else {
            "no __stack_chk_fail: compiled without -fstack-protector"
        };
        checks.push(Check {
            name: "Canary",
            enabled: Some(found),
            detail: detail.into(),
        });
    }

    if o.fortify {
        let fortified: Vec<&String> = imports
            .iter()
            .filter(|i| i.starts_with("__") && i.ends_with("_chk"))
            .collect();
        let (enabled, detail) = if fortified.is_empty() {
            (
                false,
                "no *_chk import (no -D_FORTIFY_SOURCE or nothing to fortify)".to_string(),
            )
        } else {
            let names: Vec<&str> = fortified.iter().map(|s| s.as_str()).collect();
            (
                true,
                format!("{} fortified call(s): {}", names.len(), names.join(", ")),
            )
        };
        checks.push(Check {
            name: "Fortify",
            enabled: Some(enabled),
            detail,
        });
    }

    if elf.header.e_type != elf::header::ET_REL && elf.dynamic.is_none() {
        checks.push(Check {
            name: "Static",
            enabled: None,
            detail: "statically linked: import-based checks are unreliable".into(),
        });
    }
    (checks, imports)
}

fn check_pe(pe: &PE, o: &Opts) -> (Vec<Check>, Vec<String>) {
    let mut imports: Vec<String> = pe
        .imports
        .iter()
        .map(|i| i.name.to_string())
        .filter(|n| !n.is_empty())
        .collect();
    imports.sort();
    imports.dedup();
    let mut checks = Vec::new();
    let chars = pe
        .header
        .optional_header
        .map(|h| h.windows_fields.dll_characteristics)
        .unwrap_or(0);
    let has = |flag: u16| chars & flag != 0;

    if o.nx {
        checks.push(Check {
            name: "NX / DEP",
            enabled: Some(has(IMAGE_DLLCHARACTERISTICS_NX_COMPAT)),
            detail: if has(IMAGE_DLLCHARACTERISTICS_NX_COMPAT) {
                "NX_COMPAT set"
            } else {
                "NX_COMPAT not set"
            }
            .into(),
        });
    }
    if o.pie {
        let aslr = has(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);
        let hev = has(IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA);
        let detail = match (aslr, hev) {
            (true, true) => "DYNAMIC_BASE + HIGH_ENTROPY_VA",
            (true, false) => "DYNAMIC_BASE (no high-entropy 64-bit ASLR)",
            _ => "DYNAMIC_BASE not set: image loads at its preferred base",
        };
        checks.push(Check {
            name: "ASLR",
            enabled: Some(aslr),
            detail: detail.into(),
        });
        checks.push(Check {
            name: "CFG",
            enabled: Some(has(IMAGE_DLLCHARACTERISTICS_GUARD_CF)),
            detail: if has(IMAGE_DLLCHARACTERISTICS_GUARD_CF) {
                "Control Flow Guard enabled"
            } else {
                "no Control Flow Guard"
            }
            .into(),
        });
    }
    if o.relro {
        let no_seh = has(IMAGE_DLLCHARACTERISTICS_NO_SEH);
        let safeseh = pe
            .header
            .optional_header
            .is_some_and(|h| h.data_directories.get_load_config_table().is_some());
        checks.push(Check {
            name: "SEH",
            enabled: Some(no_seh || safeseh),
            detail: if no_seh {
                "NO_SEH: image uses no structured exception handlers"
            } else if safeseh {
                "load config present (SafeSEH/CFG table)"
            } else {
                "no SafeSEH load config"
            }
            .into(),
        });
        checks.push(Check {
            name: "Integrity",
            enabled: Some(has(IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)),
            detail: if has(IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) {
                "FORCE_INTEGRITY: signature required"
            } else {
                "no forced code integrity"
            }
            .into(),
        });
    }
    if o.canary {
        checks.push(Check {
            // /GS leaves no import: the cookie lives in the load config, which needs a deeper
            // parse than goblin offers, so the check is reported as unknown rather than guessed.
            name: "GS cookie",
            enabled: None,
            detail:
                "/GS cannot be detected from headers alone (needs __security_cookie in load config)"
                    .into(),
        });
    }
    if o.fortify {
        let safe: Vec<&String> = imports
            .iter()
            .filter(|i| {
                i.ends_with("_s")
                    && (i.starts_with("str") || i.starts_with("mem") || i.starts_with("wcs"))
            })
            .collect();
        checks.push(Check {
            name: "Safe CRT",
            enabled: Some(!safe.is_empty()),
            detail: if safe.is_empty() {
                "no *_s secure CRT import".to_string()
            } else {
                format!("{} secure CRT call(s)", safe.len())
            },
        });
    }
    (checks, imports)
}
