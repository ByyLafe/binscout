mod analysis;
mod app;
mod catalog;
mod config;
mod doctor;
mod engine;
mod hex;
mod picker;
mod report;
mod triage;
mod ui;

use app::{App, PendingAction};
use catalog::{STEP_REPORT, STEPS};
use clap::Parser;
use crossterm::event::{self, Event, KeyEventKind};
use engine::StepRequest;
use engine::runner::run_step;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    target: Option<PathBuf>,

    #[arg(long)]
    run_all: bool,

    #[arg(long, short = 'p')]
    preset: Option<String>,

    #[arg(long, default_value = "md")]
    report: String,

    #[arg(long, short = 'o')]
    out: Option<PathBuf>,

    #[arg(long)]
    load: Option<PathBuf>,

    #[arg(long)]
    triage: Option<PathBuf>,

    #[arg(long)]
    online: bool,

    #[arg(long)]
    doctor: bool,

    #[arg(long)]
    list_presets: bool,
}

// println! panics on a closed pipe (`binscout --triage dir | head`).
fn out(text: &str) {
    use std::io::Write;
    let _ = std::io::stdout().write_all(text.as_bytes());
}

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();

    if cli.doctor {
        let doctor = doctor::Doctor::run();
        out(&doctor.report());
        std::process::exit(if doctor.missing().is_empty() { 0 } else { 1 });
    }

    if cli.list_presets {
        for p in config::get().presets() {
            out(&format!("{}: {}\n", p.name, p.description));
            for (s, step) in STEPS.iter().enumerate() {
                let opts: Vec<String> = step
                    .options
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| p.checked[s][*i])
                    .map(|(i, o)| match &p.values[s][i] {
                        Some(v) => format!("{} = {v}", o.label),
                        None => o.label.to_string(),
                    })
                    .collect();
                if !opts.is_empty() {
                    out(&format!("  {:<16} {}\n", step.name, opts.join(" | ")));
                }
            }
            out("\n");
        }
        if let Some(p) = config::config_path() {
            out(&format!("config file: {}\n", p.display()));
        }
        return Ok(());
    }

    if let Some(dir) = &cli.triage {
        if !dir.is_dir() {
            eprintln!("error: {} is not a directory", dir.display());
            std::process::exit(2);
        }
        let rows = triage::scan(dir, cli.online, 1000);
        out(&triage::table(&rows));
        return Ok(());
    }

    if cli.run_all {
        let Some(target) = cli.target.clone().filter(|t| t.is_file()) else {
            eprintln!("error: --run-all needs a file to analyze");
            std::process::exit(2);
        };
        return headless(target, &cli);
    }

    let mut triage_rows = None;
    if let Some(t) = &cli.target {
        if t.is_dir() {
            eprintln!("triaging {}...", t.display());
            triage_rows = Some((t.clone(), triage::scan(t, cli.online, 200)));
        } else if !t.is_file() {
            eprintln!("error: {} is not a readable file", t.display());
            std::process::exit(2);
        }
    }

    let mut app = App::new(cli.target.clone().filter(|t| t.is_file()));
    if let Some(name) = &cli.preset {
        match config::get().preset(name) {
            Some(p) => app.apply_preset(&p),
            None => {
                eprintln!("error: unknown preset \"{name}\" (see --list-presets)");
                std::process::exit(2);
            }
        }
    }
    if let Some(path) = &cli.load {
        match report::SavedReport::load(path) {
            Ok(saved) => {
                let (target, results) = saved.into_results();
                app = app.with_results(target, results);
            }
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(2);
            }
        }
    }
    if let Some((dir, rows)) = triage_rows {
        app = app.with_triage(dir, rows);
    }

    let mut terminal = ratatui::init();
    while !app.should_quit {
        terminal.draw(|f| ui::render(f, &app))?;
        if event::poll(Duration::from_millis(80))?
            && let Event::Key(key) = event::read()?
            && (key.kind == KeyEventKind::Press || key.kind == KeyEventKind::Repeat)
        {
            app.handle_key(key);
        }
        app.poll_worker();

        // sudo prompts and editors need the real terminal: leave the TUI, run, come back.
        if let Some(action) = app.pending.take() {
            ratatui::restore();
            match action {
                PendingAction::Shell(cmd) => {
                    run_shell(&cmd, true);
                    terminal = ratatui::init();
                    app.after_install();
                }
                PendingAction::Editor(path) => {
                    let editor = config::get().editor();
                    run_shell(
                        &format!(
                            "{editor} '{}'",
                            path.display().to_string().replace('\'', "'\\''")
                        ),
                        false,
                    );
                    terminal = ratatui::init();
                    app.status = format!("closed {editor}");
                }
            }
        }
    }
    ratatui::restore();
    Ok(())
}

fn run_shell(cmd: &str, wait_for_enter: bool) {
    use std::io::{BufRead, Write};
    println!("\n$ {cmd}\n");
    let status = std::process::Command::new("sh").arg("-c").arg(cmd).status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => println!("\ncommand exited with {s}"),
        Err(e) => println!("\ncould not run the command: {e}"),
    }
    if wait_for_enter {
        print!("press Enter to return to BinScout...");
        let _ = std::io::stdout().flush();
        let _ = std::io::stdin().lock().read_line(&mut String::new());
    }
}

fn headless(target: PathBuf, cli: &Cli) -> color_eyre::Result<()> {
    let target = std::fs::canonicalize(&target).unwrap_or(target);
    let name = cli.preset.clone().unwrap_or_else(|| "quick".to_string());
    let Some(preset) = config::get().preset(&name) else {
        eprintln!("error: unknown preset \"{name}\" (see --list-presets)");
        std::process::exit(2);
    };
    let out_dir = cli
        .out
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    std::fs::create_dir_all(&out_dir)?;

    let mut checked = preset.checked.clone();
    let mut values: Vec<Vec<String>> = STEPS
        .iter()
        .enumerate()
        .map(|(s, step)| {
            step.options
                .iter()
                .enumerate()
                .map(|(i, o)| {
                    preset.values[s][i].clone().unwrap_or_else(|| match o.kind {
                        catalog::OptionKind::Value { default, .. } => default.to_string(),
                        catalog::OptionKind::Flag => String::new(),
                    })
                })
                .collect()
        })
        .collect();

    let formats: Vec<&str> = cli.report.split(',').map(str::trim).collect();
    // The report format is a CLI concern; the preset must not override --report.
    checked[STEP_REPORT][0] = formats.contains(&"md");
    checked[STEP_REPORT][1] = formats.contains(&"json");
    if !checked[STEP_REPORT][0] && !checked[STEP_REPORT][1] {
        eprintln!("error: --report must contain md and/or json");
        std::process::exit(2);
    }
    values[STEP_REPORT].iter_mut().for_each(|v| v.clear());

    let mut results: Vec<Option<engine::StepResult>> = vec![None; STEPS.len()];
    let mut order: Vec<usize> = (0..STEPS.len())
        .filter(|s| *s != STEP_REPORT && checked[*s].iter().any(|c| *c))
        .collect();
    order.push(STEP_REPORT);
    eprintln!(
        "binscout: {} with preset \"{}\" ({} step(s))",
        target.display(),
        preset.name,
        order.len()
    );
    let mut failed = 0;
    for step in order {
        eprint!("  {:<28}", STEPS[step].title);
        let result = run_step(StepRequest {
            step,
            target: target.clone(),
            checked: checked[step].clone(),
            values: values[step].clone(),
            previous: results.clone(),
            out_dir: out_dir.clone(),
        });
        eprintln!("{:?} ({} ms)", result.status, result.duration_ms);
        if result.status == engine::Status::Failed {
            failed += 1;
        }
        if step == STEP_REPORT {
            for l in result.output.lines().filter(|l| l.starts_with("written: ")) {
                println!("{}", l.trim_start_matches("written: "));
            }
        }
        results[step] = Some(result);
    }
    std::process::exit(if failed > 0 { 1 } else { 0 });
}
