use crate::analysis::binary::file_regions;
use crate::analysis::{hashes, human_size, read_target, shannon_entropy, strings};
use crate::engine::runner::{expand_tilde, run_command, tool_available};
use crate::engine::{StepRequest, StepResult};
use goblin::Object;
use std::collections::{BTreeMap, BTreeSet};

fn symbols(data: &[u8]) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut imports = BTreeSet::new();
    let mut exports = BTreeSet::new();
    match Object::parse(data) {
        Ok(Object::PE(pe)) => {
            for i in &pe.imports {
                imports.insert(format!("{}!{}", i.dll.to_lowercase(), i.name));
            }
            for e in &pe.exports {
                exports.insert(e.name.unwrap_or("(unnamed)").to_string());
            }
        }
        Ok(Object::Elf(elf)) => {
            for s in elf.dynsyms.iter() {
                let name = elf.dynstrtab.get_at(s.st_name).unwrap_or("");
                if name.is_empty() {
                    continue;
                }
                if s.is_import() {
                    imports.insert(name.to_string());
                } else if s.is_function() {
                    exports.insert(name.to_string());
                }
            }
        }
        Ok(Object::Mach(goblin::mach::Mach::Binary(m))) => {
            for i in m.imports().unwrap_or_default() {
                imports.insert(i.name.to_string());
            }
            for e in m.exports().unwrap_or_default() {
                exports.insert(e.name.clone());
            }
        }
        _ => {}
    }
    (imports, exports)
}

fn diff_sets(
    result: &mut StepResult,
    title: &str,
    a: &BTreeSet<String>,
    b: &BTreeSet<String>,
    limit: usize,
) {
    let added: Vec<&String> = b.difference(a).collect();
    let removed: Vec<&String> = a.difference(b).collect();
    let common = a.intersection(b).count();
    result.push_line(format!(
        "== {title}: {common} common, {} only in A, {} only in B ==",
        removed.len(),
        added.len()
    ));
    for r in removed.iter().take(limit) {
        result.push_line(format!("  - {r}"));
    }
    if removed.len() > limit {
        result.push_line(format!("  - ... {} more", removed.len() - limit));
    }
    for a in added.iter().take(limit) {
        result.push_line(format!("  + {a}"));
    }
    if added.len() > limit {
        result.push_line(format!("  + ... {} more", added.len() - limit));
    }
    result.push_line("");
}

pub fn run(req: &StepRequest) -> StepResult {
    let mut result = StepResult::new(req.step);
    let other_str = req.value(0).trim();
    if !req.is_checked(0) || other_str.is_empty() {
        return StepResult::skipped(
            req.step,
            "no second file: press c to pick one, or check the first option and type its path",
        );
    }
    let other = expand_tilde(other_str);
    if !other.is_file() {
        return StepResult::failed(
            req.step,
            format!("{} is not a readable file", other.display()),
        );
    }
    let a = match read_target(&req.target) {
        Ok(d) => d,
        Err(e) => return StepResult::failed(req.step, e),
    };
    let b = match read_target(&other) {
        Ok(d) => d,
        Err(e) => return StepResult::failed(req.step, e),
    };
    let none = !req.checked.iter().skip(1).any(|c| *c);

    result.push_line(format!(
        "A: {}  ({}, entropy {:.3})",
        req.target.display(),
        human_size(a.len() as u64),
        shannon_entropy(&a)
    ));
    result.push_line(format!(
        "B: {}  ({}, entropy {:.3})",
        other.display(),
        human_size(b.len() as u64),
        shannon_entropy(&b)
    ));
    let (ha, hb) = (hashes::sha256_hex(&a), hashes::sha256_hex(&b));
    if ha == hb {
        result.push_line("sha256: identical files");
        return result;
    }
    result.push_line(format!("sha256 A {ha}\nsha256 B {hb}"));
    if let (Ok(ia), Ok(ib)) = (hashes::imphash(&a), hashes::imphash(&b)) {
        result.push_line(format!(
            "imphash {}",
            if ia == ib {
                format!("identical ({ia})")
            } else {
                format!("A {ia}  B {ib}")
            }
        ));
    }
    let same_prefix = a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count();
    result.push_line(format!(
        "identical prefix: {} ({}), size delta {:+}",
        human_size(same_prefix as u64),
        same_prefix,
        b.len() as i64 - a.len() as i64
    ));
    result.push_line("");

    if none || req.is_checked(1) {
        let ra: BTreeMap<String, (usize, f64)> = file_regions(&a)
            .unwrap_or_default()
            .into_iter()
            .map(|r| {
                (
                    r.name.clone(),
                    (
                        r.size,
                        shannon_entropy(
                            &a[r.offset.min(a.len())..(r.offset + r.size).min(a.len())],
                        ),
                    ),
                )
            })
            .collect();
        let rb: BTreeMap<String, (usize, f64)> = file_regions(&b)
            .unwrap_or_default()
            .into_iter()
            .map(|r| {
                (
                    r.name.clone(),
                    (
                        r.size,
                        shannon_entropy(
                            &b[r.offset.min(b.len())..(r.offset + r.size).min(b.len())],
                        ),
                    ),
                )
            })
            .collect();
        result.push_line("== Sections ==");
        result.push_line(format!(
            "  {:<20} {:>10} {:>10} {:>8} {:>8}",
            "section", "size A", "size B", "ent A", "ent B"
        ));
        let names: BTreeSet<&String> = ra.keys().chain(rb.keys()).collect();
        for n in names {
            let (sa, ea) = ra
                .get(n)
                .map(|(s, e)| (human_size(*s as u64), format!("{e:.2}")))
                .unwrap_or(("-".into(), "-".into()));
            let (sb, eb) = rb
                .get(n)
                .map(|(s, e)| (human_size(*s as u64), format!("{e:.2}")))
                .unwrap_or(("-".into(), "-".into()));
            let mark = match (ra.get(n), rb.get(n)) {
                (Some(_), None) => "  (only in A)",
                (None, Some(_)) => "  (only in B)",
                (Some((x, ex)), Some((y, ey))) if x != y || (ex - ey).abs() > 0.5 => "  *",
                _ => "",
            };
            result.push_line(format!("  {n:<20} {sa:>10} {sb:>10} {ea:>8} {eb:>8}{mark}"));
        }
        result.push_line("");
    }

    if none || req.is_checked(2) {
        let (ia, ea) = symbols(&a);
        let (ib, eb) = symbols(&b);
        diff_sets(&mut result, "Imports", &ia, &ib, 60);
        diff_sets(&mut result, "Exports", &ea, &eb, 60);
    }

    if none || req.is_checked(3) {
        let sa: BTreeSet<String> = strings::all(&a, 6).into_iter().collect();
        let sb: BTreeSet<String> = strings::all(&b, 6).into_iter().collect();
        diff_sets(&mut result, "Strings (>= 6 chars)", &sa, &sb, 80);
    }

    if req.is_checked(4) {
        if tool_available("ssdeep") {
            let raw = run_command(
                "ssdeep",
                &[
                    "-d".into(),
                    "-b".into(),
                    req.target.to_string_lossy().into_owned(),
                    other.to_string_lossy().into_owned(),
                ],
            );
            let line = raw
                .stdout
                .lines()
                .find(|l| l.contains("matches"))
                .map(str::to_string);
            result.push_line(format!(
                "== ssdeep ==\n  {}",
                line.unwrap_or_else(|| "similarity below ssdeep's threshold (no match)".into())
            ));
            result.raw.push(raw);
        } else {
            result.push_line("== ssdeep == not installed");
        }
    }
    result
}
