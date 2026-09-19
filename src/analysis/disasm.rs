use crate::engine::runner::{absorb, run_command, tool_available};
use crate::engine::{StepRequest, StepResult};
use goblin::Object;

type CodeSection = (u64, u64, String);

fn entry_info(data: &[u8]) -> Option<(u64, Option<CodeSection>)> {
    match Object::parse(data).ok()? {
        Object::Elf(elf) => {
            let entry = elf.header.e_entry;
            let sec = elf.section_headers.iter().find(|sh| {
                sh.sh_flags as u32 & goblin::elf::section_header::SHF_EXECINSTR != 0
                    && entry >= sh.sh_addr
                    && entry < sh.sh_addr + sh.sh_size
            });
            Some((
                entry,
                sec.map(|sh| {
                    (
                        sh.sh_addr,
                        sh.sh_addr + sh.sh_size,
                        elf.shdr_strtab
                            .get_at(sh.sh_name)
                            .unwrap_or("?")
                            .to_string(),
                    )
                }),
            ))
        }
        Object::PE(pe) => {
            let entry = pe.image_base + pe.entry as u64;
            let sec = pe.sections.iter().find(|s| {
                let start = pe.image_base + s.virtual_address as u64;
                entry >= start && entry < start + s.virtual_size.max(s.size_of_raw_data) as u64
            });
            Some((
                entry,
                sec.map(|s| {
                    let start = pe.image_base + s.virtual_address as u64;
                    (
                        start,
                        start + s.virtual_size.max(s.size_of_raw_data) as u64,
                        s.name().unwrap_or("?").to_string(),
                    )
                }),
            ))
        }
        Object::Mach(goblin::mach::Mach::Binary(m)) => Some((m.entry, None)),
        _ => None,
    }
}

pub fn run(req: &StepRequest) -> StepResult {
    let mut result = StepResult::new(req.step);
    let data = match crate::analysis::read_target(&req.target) {
        Ok(d) => d,
        Err(e) => return StepResult::failed(req.step, e),
    };
    let target = req.target.to_string_lossy().into_owned();
    let none = !req.any_checked();
    let intel = req.is_checked(1);
    let mut base_args: Vec<String> = vec!["-d".into(), "--no-show-raw-insn".into()];
    if intel {
        base_args.push("-M".into());
        base_args.push("intel".into());
    }

    let info = entry_info(&data);
    if none || req.is_checked(0) {
        let span = req
            .value(0)
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|n| *n > 0)
            .unwrap_or(512);
        match &info {
            Some((entry, sec)) => {
                let entry = *entry;
                result.push_line(format!(
                    "entry point 0x{entry:x}{}",
                    sec.as_ref()
                        .map(|(_, _, n)| format!(" in `{n}`"))
                        .unwrap_or_default()
                ));
                let mut args = base_args.clone();
                args.push(format!("--start-address=0x{entry:x}"));
                args.push(format!("--stop-address=0x{:x}", entry + span));
                args.push(target.clone());
                let raw = run_command("objdump", &args);

                // objdump repeats a header per section; only the decoded instructions are shown.
                let body: Vec<&str> = raw
                    .stdout
                    .lines()
                    .skip_while(|l| {
                        !l.contains(':')
                            || !l.trim_start().starts_with(|c: char| c.is_ascii_hexdigit())
                    })
                    .collect();
                result.push_line(format!("$ {}", raw.command));
                if body.is_empty() {
                    result.push_line(if raw.stderr.is_empty() {
                        "no code decoded (unsupported architecture for this objdump?)".to_string()
                    } else {
                        raw.stderr.trim().to_string()
                    });
                } else {
                    for l in body {
                        result.push_line(l);
                    }
                }
                result.raw.push(raw);
                result.push_line("");
            }
            None => result.push_line("entry point unknown (not an ELF/PE/Mach-O)\n"),
        }
    }

    if req.is_checked(2) {
        let r2 = ["rizin", "r2", "radare2"]
            .into_iter()
            .find(|t| tool_available(t));
        match r2 {
            Some(bin) => {
                result.push_line(format!("== Functions ({bin}) =="));
                let args = vec![
                    "-q".to_string(),
                    "-e".to_string(),
                    "scr.color=0".to_string(),
                    "-c".to_string(),
                    "aaa; afl".to_string(),
                    target.clone(),
                ];
                absorb(&mut result, run_command(bin, &args));
            }
            None => {
                result.push_line(
                    "== Function symbols (objdump -t; install rizin for real function recovery) ==",
                );
                let args = vec!["-t".to_string(), "-T".to_string(), target.clone()];
                let raw = run_command("objdump", &args);
                let mut funcs: Vec<String> = raw
                    .stdout
                    .lines()
                    .filter(|l| l.contains(" F ") || l.contains("DF "))
                    .map(|l| {
                        let mut it = l.split_whitespace();
                        let addr = it.next().unwrap_or("");
                        let name = it.last().unwrap_or("");
                        format!("  0x{addr}  {name}")
                    })
                    .collect();
                funcs.sort();
                funcs.dedup();
                if funcs.is_empty() {
                    result.push_line("  no function symbols (stripped binary)");
                }
                for f in funcs.iter().take(500) {
                    result.push_line(f);
                }
                if funcs.len() > 500 {
                    result.push_line(format!("  ... {} more", funcs.len() - 500));
                }
                result.raw.push(raw);
                result.push_line("");
            }
        }
    }

    if req.is_checked(3) {
        let mut args = base_args.clone();
        if let Some((_, Some((start, end, name)))) = &info {
            args.push(format!("--start-address=0x{start:x}"));
            args.push(format!("--stop-address=0x{end:x}"));
            result.push_line(format!("== Full disassembly of `{name}` =="));
        } else {
            result.push_line("== Full disassembly ==");
        }
        args.push(target);
        absorb(&mut result, run_command("objdump", &args));
    }
    result
}
