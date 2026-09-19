use super::{Message, RawOutput, Status, StepRequest, StepResult};
use crate::analysis;
use crate::catalog::{
    self, STEP_ANTI, STEP_BINWALK, STEP_CAPA, STEP_COMPARE, STEP_CONTAINER, STEP_DISASM,
    STEP_ENTROPY, STEP_FILE, STEP_HASHES, STEP_IOCS, STEP_MITIGATIONS, STEP_PACKER, STEP_REPORT,
    STEP_SECTIONS, STEP_STRINGS, STEP_YARA,
};
use std::cell::RefCell;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::Sender;
use std::time::Instant;

thread_local! {

    static PROGRESS: RefCell<Option<Sender<Message>>> = const { RefCell::new(None) };

    // Thread-local rather than a parameter threaded through every runner: the preview
    // must reuse the exact code path Space executes, otherwise the two drift apart.
    static DRY_RUN: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
}

pub fn dry_run() -> bool {
    DRY_RUN.with(|d| d.borrow().is_some())
}

pub fn preview(req: StepRequest) -> (Vec<String>, StepResult) {
    DRY_RUN.with(|d| *d.borrow_mut() = Some(Vec::new()));
    let result = run_step(req);
    let commands = DRY_RUN.with(|d| d.borrow_mut().take().unwrap_or_default());
    (commands, result)
}

pub fn set_progress(sender: Option<Sender<Message>>) {
    PROGRESS.with(|p| *p.borrow_mut() = sender);
}

fn progress(line: &str) {
    PROGRESS.with(|p| {
        if let Some(tx) = p.borrow().as_ref() {
            let _ = tx.send(Message::Line(line.to_string()));
        }
    });
}

pub fn tool_path(name: &str) -> Option<PathBuf> {
    which::which(name).ok()
}

pub fn tool_available(name: &str) -> bool {
    tool_path(name).is_some()
}

pub fn run_command(program: &str, args: &[String]) -> RawOutput {
    let command = std::iter::once(program.to_string())
        .chain(args.iter().map(|a| shell_quote(a)))
        .collect::<Vec<_>>()
        .join(" ");
    if DRY_RUN.with(|d| {
        if let Some(list) = d.borrow_mut().as_mut() {
            list.push(command.clone());
            true
        } else {
            false
        }
    }) {
        return RawOutput {
            command,
            exit_code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
        };
    }
    progress(&format!("$ {command}"));

    let mut child = match Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return RawOutput {
                command,
                exit_code: None,
                stdout: String::new(),
                stderr: format!("failed to spawn `{program}`: {e}"),
            };
        }
    };

    // stderr is drained on its own thread: reading stdout line by line while a chatty
    // tool fills the stderr pipe would deadlock both processes.
    let stderr_handle = child.stderr.take().map(|err| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = std::io::Read::read_to_end(&mut BufReader::new(err), &mut buf);
            String::from_utf8_lossy(&buf).into_owned()
        })
    });
    let mut stdout = String::new();
    if let Some(out) = child.stdout.take() {
        let mut reader = BufReader::new(out);
        let mut raw = Vec::new();
        loop {
            raw.clear();
            match reader.read_until(b'\n', &mut raw) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let line = String::from_utf8_lossy(&raw);
                    progress(line.trim_end_matches(['\n', '\r']));
                    stdout.push_str(&line);
                }
            }
        }
    }
    let exit_code = child.wait().ok().and_then(|st| st.code());
    let stderr = stderr_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();
    RawOutput {
        command,
        exit_code,
        stdout,
        stderr,
    }
}

fn shell_quote(arg: &str) -> String {
    if arg
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_./=:,~".contains(c))
    {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

pub fn absorb(result: &mut StepResult, raw: RawOutput) -> bool {
    let ok = raw.exit_code == Some(0);
    result.push_line(format!("$ {}", raw.command));
    if !raw.stdout.trim().is_empty() {
        result.push_line(raw.stdout.trim_end());
    }
    if !raw.stderr.trim().is_empty() {
        result.push_line(format!("[stderr]\n{}", raw.stderr.trim_end()));
    }
    if !ok {
        result.status = Status::Failed;
        result.push_line(match raw.exit_code {
            Some(c) => format!("[exit code {c}]"),
            None => "[command could not be started]".to_string(),
        });
    }
    result.push_line("");
    result.raw.push(raw);
    ok
}

pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    } else if path == "~"
        && let Some(home) = dirs::home_dir()
    {
        return home;
    }
    PathBuf::from(path)
}

pub fn extracted_dir(target: &Path) -> PathBuf {
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    PathBuf::from(format!("_{name}.extracted"))
}

pub fn run_step(req: StepRequest) -> StepResult {
    let started = Instant::now();
    let step = catalog::step(req.step);

    let mut result = if req.step != STEP_REPORT && !req.target.is_file() {
        StepResult::skipped(
            req.step,
            format!("target is not a readable file: {}", req.target.display()),
        )
    } else if let Some(tool) = step.tool.filter(|t| !tool_available(t)) {
        StepResult::skipped(
            req.step,
            format!("`{tool}` is not installed or not in $PATH"),
        )
    } else {
        match req.step {
            STEP_FILE => run_file(&req),
            STEP_HASHES => analysis::hashes::run(&req),
            STEP_PACKER => analysis::binary::packer::run(&req),
            STEP_CONTAINER => analysis::container::run(&req),
            STEP_BINWALK => run_binwalk(&req),
            STEP_ENTROPY => analysis::binary::entropy::run(&req),
            STEP_SECTIONS => analysis::binary::sections::run(&req),
            STEP_MITIGATIONS => analysis::binary::mitigations::run(&req),
            STEP_ANTI => analysis::binary::anti::run(&req),
            STEP_STRINGS => run_strings(&req),
            STEP_IOCS => analysis::iocs::run(&req),
            STEP_YARA => run_yara(&req),
            STEP_CAPA => run_capa(&req),
            STEP_DISASM => analysis::disasm::run(&req),
            STEP_COMPARE => analysis::compare::run(&req),
            STEP_REPORT => crate::report::run(&req),
            _ => StepResult::skipped(req.step, "unknown step"),
        }
    };

    result.options = req.checked_labels();
    result.duration_ms = started.elapsed().as_millis();
    result
}

fn target_arg(req: &StepRequest) -> String {
    req.target.to_string_lossy().into_owned()
}

fn run_file(req: &StepRequest) -> StepResult {
    let mut result = StepResult::new(req.step);
    let mut args: Vec<String> = Vec::new();
    let flags = ["-i", "-z", "-k", "-L", "--extension"];
    for (i, f) in flags.iter().enumerate() {
        if req.is_checked(i) {
            args.push(f.to_string());
        }
    }
    args.push(target_arg(req));
    let mut raw = run_command("file", &args);

    raw.stdout = raw.stdout.replace("\\012- ", "\n  - ");
    let ok = absorb(&mut result, raw.clone());
    if ok && let Some(parsed) = analysis::parsers::file_cmd::parse(&raw.stdout) {
        result.push_line(parsed.summary());
    }
    result
}

fn run_binwalk(req: &StepRequest) -> StepResult {
    let mut result = StepResult::new(req.step);
    let mut args: Vec<String> = Vec::new();
    let flags = ["-e", "-M", "-B", "-A", "-E", "-J", "-z"];
    for (i, f) in flags.iter().enumerate() {
        if req.is_checked(i) {
            args.push(f.to_string());
        }
    }
    if req.is_checked(4) && !req.is_checked(5) {
        // binwalk -E opens a plot window unless -N is given; there is no display behind a TUI.
        args.push("-N".to_string());
    }
    for (opt, flag) in [(7, "-R"), (8, "-y"), (9, "-x")] {
        if req.is_checked(opt) && !req.value(opt).is_empty() {
            args.push(format!("{flag}={}", req.value(opt)));
        }
    }
    let scanning = args
        .iter()
        .any(|a| matches!(a.as_str(), "-B" | "-A" | "-E" | "-e" | "-z") || a.starts_with("-R="));
    if !scanning {
        // binwalk exits with an error when no scan type is requested.
        args.insert(0, "-B".to_string());
    }
    args.push(target_arg(req));
    let raw = run_command("binwalk", &args);
    let ok = absorb(&mut result, raw.clone());
    if ok {
        let sigs = analysis::parsers::binwalk::parse(&raw.stdout);
        if !sigs.is_empty() {
            result.push_line(format!("{} signature(s) found:", sigs.len()));
            for s in &sigs {
                result.push_line(format!("  0x{:08X}  {}", s.offset, s.description));
            }
        }
        if req.is_checked(0) {
            let dir = extracted_dir(&req.target);
            if dir.is_dir() {
                result.push_line(format!("extracted files are in {}", dir.display()));
            }
        }
    }
    result
}

fn run_strings(req: &StepRequest) -> StepResult {
    let mut result = StepResult::new(req.step);
    let min_len = if req.is_checked(2) && !req.value(2).is_empty() {
        Some(req.value(2).to_string())
    } else {
        None
    };

    // Checking only the minimum length must still produce output, so classic strings
    // stay on unless UTF-16 or FLOSS was picked explicitly.
    let classic = req.is_checked(0) || !(req.is_checked(1) || req.is_checked(3));
    let utf16 = req.is_checked(1);

    if (classic || utf16) && !tool_available("strings") {
        let min = min_len.as_deref().and_then(|n| n.parse().ok()).unwrap_or(4);
        match analysis::read_target(&req.target) {
            Ok(data) => {
                if classic {
                    let v = analysis::strings::ascii(&data, min);
                    result.push_line(format!(
                        "== ASCII strings: {} (native extraction, `strings` not installed) ==",
                        v.len()
                    ));
                    for l in v {
                        result.push_line(l);
                    }
                }
                if utf16 {
                    let v = analysis::strings::utf16le(&data, min);
                    result.push_line(format!(
                        "== UTF-16LE strings: {} (native extraction) ==",
                        v.len()
                    ));
                    for l in v {
                        result.push_line(l);
                    }
                }
            }
            Err(e) => return StepResult::failed(req.step, e),
        }
    } else if classic || utf16 {
        let mut encodings = Vec::new();
        if classic {
            encodings.push(None);
        }
        if utf16 {
            encodings.push(Some("l"));
        }
        for enc in encodings {
            let mut args = vec!["-a".to_string()];
            if let Some(e) = enc {
                args.push("-e".to_string());
                args.push(e.to_string());
            }
            if let Some(n) = &min_len {
                args.push("-n".to_string());
                args.push(n.clone());
            }
            args.push(target_arg(req));
            let raw = run_command("strings", &args);
            let count = raw.stdout.lines().count();
            let label = if enc.is_some() { "UTF-16LE" } else { "ASCII" };
            result.push_line(format!("== {label} strings: {count} ==",));
            absorb(&mut result, raw);
        }
    }

    if req.is_checked(3) {
        if tool_available("floss") {
            let mut args = vec![target_arg(req)];
            if let Some(n) = &min_len {
                args.push("-n".to_string());
                args.push(n.clone());
            }
            // The file goes before --no: argparse would otherwise swallow it as a value of --no.
            args.push("--no".to_string());
            args.push("static".to_string());
            result.push_line("== FLOSS decoded / stack / tight strings ==");
            absorb(&mut result, run_command("floss", &args));
        } else {
            result.push_line(
                "[floss] not installed: skipping decoded strings (pip install flare-floss)",
            );
        }
    }
    result
}

fn yara_rule_files(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        return vec![path.to_path_buf()];
    }
    if path.is_dir() {
        // Community rule sets ship an index file that includes everything; compiling every
        // .yar separately would fail on files that depend on each other.
        for idx in ["index.yar", "index.yara"] {
            let p = path.join(idx);
            if p.is_file() {
                return vec![p];
            }
        }
        let mut files: Vec<PathBuf> = walkdir::WalkDir::new(path)
            .max_depth(3)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
            .map(|e| e.into_path())
            .filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("yar" | "yara")))
            .collect();
        files.sort();
        return files;
    }
    Vec::new()
}

fn run_yara(req: &StepRequest) -> StepResult {
    let mut result = StepResult::new(req.step);
    let mut rule_sources: Vec<PathBuf> = Vec::new();
    for opt in [0, 1] {
        if req.is_checked(opt) && !req.value(opt).is_empty() {
            rule_sources.push(expand_tilde(req.value(opt)));
        }
    }

    if req.is_checked(0)
        && req.value(0) == "~/.config/binscout/rules"
        && let Some(cfg) = &crate::config::get().yara_rules
    {
        rule_sources[0] = expand_tilde(cfg);
    }
    if rule_sources.is_empty() {
        return StepResult::skipped(
            req.step,
            "no rules selected: check \"Default community rules\" or \"Custom rules\" and give a path\n\
             (e.g. git clone https://github.com/Yara-Rules/rules ~/.config/binscout/rules)",
        );
    }

    let mut targets = vec![req.target.clone()];
    if req.is_checked(3) {
        let dir = extracted_dir(&req.target);
        if dir.is_dir() {
            targets.push(dir);
        } else {
            result.push_line(format!(
                "[note] {} not found: run binwalk with extraction first",
                dir.display()
            ));
        }
    }

    let mut matches = 0usize;
    for src in &rule_sources {
        let files = yara_rule_files(src);
        if files.is_empty() {
            result.status = Status::Failed;
            if src.exists() {
                result.push_line(format!("no .yar/.yara rules found in {}", src.display()));
            } else {
                result.push_line(format!("rules path does not exist: {}", src.display()));
            }
            continue;
        }
        for rules in files {
            for target in &targets {
                let mut args = Vec::new();
                if req.is_checked(2) {
                    args.push("-s".to_string());
                }
                if target.is_dir() {
                    args.push("-r".to_string());
                }
                args.push(rules.to_string_lossy().into_owned());
                args.push(target.to_string_lossy().into_owned());
                let raw = run_command("yara", &args);
                if raw.exit_code == Some(0) {
                    matches += raw
                        .stdout
                        .lines()
                        .filter(|l| !l.starts_with("0x") && !l.trim().is_empty())
                        .count();

                    if raw.stdout.trim().is_empty() {
                        result.raw.push(raw);
                        continue;
                    }
                }
                absorb(&mut result, raw);
            }
        }
    }

    // Big rule sets always contain a few files that no longer compile; a match elsewhere
    // is more useful than a failed step.
    if matches > 0 && result.status == Status::Failed {
        result.status = Status::Ok;
    }
    result.push_line(format!("{matches} rule match(es)"));
    result
}

fn run_capa(req: &StepRequest) -> StepResult {
    let mut result = StepResult::new(req.step);
    let mut args: Vec<String> = Vec::new();
    if req.is_checked(1) {
        args.push("-v".to_string());
    }
    if req.is_checked(2) && !req.value(2).is_empty() {
        args.push("-t".to_string());
        args.push(req.value(2).to_string());
    }
    args.push(target_arg(req));
    absorb(&mut result, run_command("capa", &args));
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::STEPS;

    fn request(step: usize, checked: &[usize], values: &[(usize, &str)]) -> StepRequest {
        let n = STEPS[step].options.len();
        let mut req = StepRequest {
            step,

            target: Some(PathBuf::from("/bin/ls"))
                .filter(|p| p.is_file())
                .unwrap_or_else(|| std::env::current_exe().unwrap()),
            checked: vec![false; n],
            values: vec![String::new(); n],
            previous: vec![None; STEPS.len()],
            out_dir: std::env::temp_dir(),
        };
        for c in checked {
            req.checked[*c] = true;
        }
        for (i, v) in values {
            req.values[*i] = v.to_string();
        }
        req
    }

    #[test]
    fn native_steps_run_on_an_elf() {
        let hashes = run_step(request(STEP_HASHES, &[0, 1, 2, 4], &[]));
        let packer = run_step(request(STEP_PACKER, &[], &[]));
        assert_eq!(packer.status, Status::Ok, "{}", packer.output);
        assert!(packer.output.contains("verdict"));
        let anti = run_step(request(STEP_ANTI, &[], &[]));
        assert_eq!(anti.status, Status::Ok, "{}", anti.output);
        let iocs = run_step(request(STEP_IOCS, &[], &[]));
        assert_eq!(iocs.status, Status::Ok, "{}", iocs.output);
        let container = run_step(request(STEP_CONTAINER, &[], &[]));
        assert_eq!(container.status, Status::Skipped);
        let compare = run_step(request(STEP_COMPARE, &[], &[]));
        assert_eq!(compare.status, Status::Skipped);
        assert_eq!(hashes.status, Status::Ok, "{}", hashes.output);
        assert!(hashes.output.contains("sha256  "));
        assert!(hashes.output.contains("imphash n/a"));

        let entropy = run_step(request(
            STEP_ENTROPY,
            &[0, 1, 2, 3, 4],
            &[(2, "4096"), (4, "6.5")],
        ));
        assert_eq!(entropy.status, Status::Ok, "{}", entropy.output);
        assert!(entropy.output.contains("overall entropy"));
        assert!(entropy.output.contains(".text"));

        let sections = run_step(request(STEP_SECTIONS, &[0, 1, 2, 3, 4], &[]));
        assert_eq!(sections.status, Status::Ok, "{}", sections.output);
        assert!(sections.output.contains("== ELF header =="));
        assert!(sections.output.contains("== Imports"));

        let mitig = run_step(request(STEP_MITIGATIONS, &[], &[]));
        assert_eq!(mitig.status, Status::Ok, "{}", mitig.output);
        assert!(mitig.output.contains("NX"));
        assert!(mitig.output.contains("mitigations enabled"));
    }

    #[test]
    fn report_needs_previous_results() {
        let empty = run_step(request(STEP_REPORT, &[], &[]));
        assert_eq!(empty.status, Status::Skipped);
    }

    #[test]
    fn missing_target_is_skipped() {
        let mut req = request(STEP_FILE, &[], &[]);
        req.target = PathBuf::from("/nonexistent/file");
        assert_eq!(run_step(req).status, Status::Skipped);
    }
}
