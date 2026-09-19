use crate::catalog::{OptionKind, STEP_COMPARE, STEP_REPORT, STEPS};
use crate::config::{self, Preset};
use crate::doctor::Doctor;
use crate::engine::runner::{preview, run_step, set_progress, tool_available};
use crate::engine::{Message, StepRequest, StepResult};
use crate::hex::HexView;
use crate::picker::FilePicker;
use crate::triage;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::cell::Cell;
use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, channel};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Steps,
    Options,
    Output,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickerPurpose {
    Target,

    CompareWith,
}

pub enum Mode {
    Normal,

    ValueInput {
        step: usize,
        opt: usize,
        buffer: String,
    },
    FilePicker {
        picker: Box<FilePicker>,
        purpose: PickerPurpose,
    },

    Doctor {
        doctor: Box<Doctor>,
        selected: usize,
    },

    Presets {
        selected: usize,
    },

    Search {
        buffer: String,
    },
    Hex(Box<HexView>),

    HexGoto {
        view: Box<HexView>,
        buffer: String,
    },

    Triage {
        dir: PathBuf,
        rows: Vec<triage::Row>,
        selected: usize,
    },
}

pub enum PendingAction {
    Shell(String),

    Editor(PathBuf),
}

pub struct Running {
    pub step: usize,
    pub started: Instant,
    rx: Receiver<Message>,
}

pub struct App {
    pub target: Option<PathBuf>,
    pub focus: Focus,
    pub mode: Mode,
    pub selected: usize,
    pub selected_right: usize,
    pub checked: Vec<Vec<bool>>,
    pub values: Vec<Vec<String>>,
    pub results: Vec<Option<StepResult>>,
    pub output_scroll: u16,

    pub output_width: Cell<u16>,
    pub running: Option<Running>,

    pub live: Vec<String>,

    pub queue: VecDeque<usize>,
    pub missing_tools: HashSet<&'static str>,
    pub status: String,
    pub should_quit: bool,
    pub pending: Option<PendingAction>,
    pub search: Option<String>,
    pub presets: Vec<Preset>,

    pub triage_job: Option<(PathBuf, Receiver<Vec<triage::Row>>)>,

    pub show_commands: bool,

    pub preview: Vec<String>,

    pub preview_note: String,
}

impl App {
    pub fn new(target: Option<PathBuf>) -> Self {
        let checked = STEPS.iter().map(|s| vec![false; s.options.len()]).collect();
        let values = STEPS
            .iter()
            .map(|s| {
                s.options
                    .iter()
                    .map(|o| match o.kind {
                        OptionKind::Value { default, .. } => default.to_string(),
                        OptionKind::Flag => String::new(),
                    })
                    .collect()
            })
            .collect();
        let missing_tools = detect_missing_tools();
        let cfg = config::get();
        let status = if let Some(err) = &cfg.load_error {
            format!("config error: {err}")
        } else if missing_tools.is_empty() {
            match &target {
                Some(t) => format!("target: {}", t.display()),
                None => "no target: press @ to pick a file".to_string(),
            }
        } else {
            let mut names: Vec<&str> = missing_tools.iter().copied().collect();
            names.sort();
            format!(
                "{} tool(s) missing: {} (press i to install)",
                names.len(),
                names.join(", ")
            )
        };
        let mut app = Self {
            target: target.map(|t| std::fs::canonicalize(&t).unwrap_or(t)),
            focus: Focus::Steps,
            mode: Mode::Normal,
            selected: 0,
            selected_right: 0,
            checked,
            values,
            results: vec![None; STEPS.len()],
            output_scroll: 0,
            output_width: Cell::new(80),
            running: None,
            live: Vec::new(),
            queue: VecDeque::new(),
            missing_tools,
            status,
            should_quit: false,
            pending: None,
            search: None,
            presets: cfg.presets(),
            triage_job: None,
            show_commands: false,
            preview: Vec::new(),
            preview_note: String::new(),
        };
        if let Some(name) = &cfg.default_preset {
            if let Some(p) = cfg.preset(name) {
                app.apply_preset(&p);
            } else {
                app.status = format!("config: unknown default_preset \"{name}\"");
            }
        }
        app
    }

    pub fn with_results(mut self, target: PathBuf, results: Vec<Option<StepResult>>) -> Self {
        let loaded = results.iter().flatten().count();
        self.results = results;
        self.target = Some(std::fs::canonicalize(&target).unwrap_or(target));
        self.status = format!("session restored: {loaded} step result(s) loaded");
        self
    }

    pub fn with_triage(mut self, dir: PathBuf, rows: Vec<triage::Row>) -> Self {
        self.status = format!("{} file(s) triaged in {}", rows.len(), dir.display());
        self.mode = Mode::Triage {
            dir,
            rows,
            selected: 0,
        };
        self
    }

    pub fn refresh_preview(&mut self) {
        if !self.show_commands {
            return;
        }
        let Some(target) = self.target.clone() else {
            self.preview = vec!["(no target file yet)".to_string()];
            return;
        };
        let step = self.selected;
        let (commands, result) = preview(StepRequest {
            step,
            target,
            checked: self.checked[step].clone(),
            values: self.values[step].clone(),
            previous: self.results.clone(),
            out_dir: self.out_dir(),
        });
        self.preview = commands;
        self.preview_note = match result.status {
            crate::engine::Status::Ok => {
                let native = STEPS[step].tool.is_none();
                let mut note = if native {
                    "(no external command: native Rust analysis)".to_string()
                } else {
                    "(nothing would run)".to_string()
                };
                if let Some(w) = result
                    .output
                    .lines()
                    .find(|l| l.starts_with("would write "))
                {
                    note = format!("({w})");
                }
                note
            }
            _ => format!(
                "(would be skipped: {})",
                result.output.lines().next().unwrap_or("")
            ),
        };
    }

    pub fn option_count(&self) -> usize {
        STEPS[self.selected].options.len()
    }

    pub fn is_running(&self, step: usize) -> bool {
        self.running.as_ref().is_some_and(|r| r.step == step)
    }

    pub fn out_dir(&self) -> PathBuf {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    }

    pub fn apply_preset(&mut self, preset: &Preset) {
        self.checked = preset.checked.clone();
        for (step, vals) in preset.values.iter().enumerate() {
            for (opt, v) in vals.iter().enumerate() {
                if let Some(v) = v {
                    self.values[step][opt] = v.clone();
                }
            }
        }
        let n: usize = self
            .checked
            .iter()
            .map(|s| s.iter().filter(|c| **c).count())
            .sum();
        self.status = format!(
            "preset \"{}\" applied: {n} option(s) checked, press r to run",
            preset.name
        );
        if !preset.unknown.is_empty() {
            self.status = format!("preset \"{}\": {}", preset.name, preset.unknown.join("; "));
        }
    }

    pub fn open_doctor(&mut self) {
        let doctor = Box::new(Doctor::run());

        let selected = doctor
            .tools
            .iter()
            .position(|t| !t.installed())
            .unwrap_or(0);
        self.mode = Mode::Doctor { doctor, selected };
    }

    pub fn after_install(&mut self) {
        self.missing_tools = detect_missing_tools();
        self.open_doctor();
        self.status = if self.missing_tools.is_empty() {
            "all tools are installed".to_string()
        } else {
            format!("{} tool(s) still missing", self.missing_tools.len())
        };
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }
        match std::mem::replace(&mut self.mode, Mode::Normal) {
            Mode::Normal => self.handle_normal(key),
            Mode::ValueInput { step, opt, buffer } => {
                self.handle_value_input(key, step, opt, buffer)
            }
            Mode::FilePicker { picker, purpose } => self.handle_picker(key, picker, purpose),
            Mode::Doctor { doctor, selected } => self.handle_doctor(key, doctor, selected),
            Mode::Presets { selected } => self.handle_presets(key, selected),
            Mode::Search { buffer } => self.handle_search(key, buffer),
            Mode::Hex(view) => self.handle_hex(key, view),
            Mode::HexGoto { view, buffer } => self.handle_hex_goto(key, view, buffer),
            Mode::Triage {
                dir,
                rows,
                selected,
            } => self.handle_triage(key, dir, rows, selected),
        }
    }

    fn handle_normal(&mut self, key: KeyEvent) {
        let steps = STEPS.len();
        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => self.should_quit = true,
            KeyCode::Esc => match self.focus {
                Focus::Output => self.focus = Focus::Options,
                Focus::Options => self.focus = Focus::Steps,
                Focus::Steps => self.should_quit = true,
            },
            KeyCode::Char('@') => self.open_picker(PickerPurpose::Target),
            KeyCode::Char('c') | KeyCode::Char('C') => self.open_picker(PickerPurpose::CompareWith),
            KeyCode::Char('i') | KeyCode::Char('I') => self.open_doctor(),
            KeyCode::Char('p') | KeyCode::Char('P') => self.mode = Mode::Presets { selected: 0 },
            KeyCode::Char('x') | KeyCode::Char('X') => self.open_hex(0),
            KeyCode::Char('v') | KeyCode::Char('V') => {
                self.show_commands = !self.show_commands;
                self.refresh_preview();
                self.status = if self.show_commands {
                    "showing the command behind each option (v to hide)".into()
                } else {
                    "command preview hidden".into()
                };
            }
            KeyCode::Char('t') | KeyCode::Char('T') => self.open_triage(),
            KeyCode::Char(' ') => self.run_current(),
            KeyCode::Char('r') | KeyCode::Char('R') => self.run_all_checked(),
            KeyCode::Char('o') | KeyCode::Char('O') => self.toggle_output(),
            KeyCode::Char('/') if self.focus == Focus::Output => {
                self.mode = Mode::Search {
                    buffer: self.search.clone().unwrap_or_default(),
                };
            }
            KeyCode::Char('n') if self.focus == Focus::Output => self.jump_search(true),
            KeyCode::Char('N') if self.focus == Focus::Output => self.jump_search(false),
            KeyCode::Char('e') | KeyCode::Char('E') if self.focus == Focus::Output => {
                self.open_in_editor()
            }
            KeyCode::Char('y') | KeyCode::Char('Y') if self.focus == Focus::Output => {
                self.copy_output()
            }
            KeyCode::Tab => self.select_step((self.selected + 1) % steps),
            KeyCode::BackTab => self.select_step((self.selected + steps - 1) % steps),
            KeyCode::Up => match self.focus {
                Focus::Steps => self.select_step((self.selected + steps - 1) % steps),
                Focus::Options => {
                    let n = self.option_count();
                    self.selected_right = (self.selected_right + n - 1) % n;
                }
                Focus::Output => self.output_scroll = self.output_scroll.saturating_sub(1),
            },
            KeyCode::Down => match self.focus {
                Focus::Steps => self.select_step((self.selected + 1) % steps),
                Focus::Options => {
                    self.selected_right = (self.selected_right + 1) % self.option_count()
                }
                Focus::Output => self.output_scroll = self.output_scroll.saturating_add(1),
            },
            KeyCode::PageUp if self.focus == Focus::Output => {
                self.output_scroll = self.output_scroll.saturating_sub(20)
            }
            KeyCode::PageDown if self.focus == Focus::Output => {
                self.output_scroll = self.output_scroll.saturating_add(20)
            }
            KeyCode::Home if self.focus == Focus::Output => self.output_scroll = 0,
            KeyCode::End if self.focus == Focus::Output => self.output_scroll = u16::MAX / 2,
            KeyCode::Left => match self.focus {
                Focus::Output => self.focus = Focus::Options,
                Focus::Options => self.focus = Focus::Steps,
                Focus::Steps => {}
            },
            KeyCode::Right => match self.focus {
                Focus::Steps => self.focus = Focus::Options,
                Focus::Options => {
                    if self.results[self.selected].is_some() || self.is_running(self.selected) {
                        self.focus = Focus::Output;
                    }
                }
                Focus::Output => {}
            },
            KeyCode::Enter => match self.focus {
                Focus::Steps => {
                    self.selected_right = 0;
                    self.focus = Focus::Options;
                }
                Focus::Options => self.toggle_option(),
                Focus::Output => {}
            },
            _ => {}
        }
    }

    fn select_step(&mut self, step: usize) {
        self.selected = step;
        self.selected_right = 0;
        self.output_scroll = 0;
        self.refresh_preview();
        if self.focus == Focus::Output && self.results[step].is_none() && !self.is_running(step) {
            self.focus = Focus::Options;
        }
    }

    fn toggle_option(&mut self) {
        let (step, opt) = (self.selected, self.selected_right);
        let def = &STEPS[step].options[opt];
        if self.checked[step][opt] {
            self.checked[step][opt] = false;
            self.refresh_preview();
            return;
        }
        match def.kind {
            OptionKind::Flag => {
                self.checked[step][opt] = true;
                self.refresh_preview();
            }
            OptionKind::Value { .. } => {
                let buffer = self.values[step][opt].clone();
                self.mode = Mode::ValueInput { step, opt, buffer };
            }
        }
    }

    fn toggle_output(&mut self) {
        if self.focus == Focus::Output {
            self.focus = Focus::Options;
        } else if self.results[self.selected].is_some() || self.is_running(self.selected) {
            self.focus = Focus::Output;
        } else {
            self.status = "no output yet for this step: press Space to run it".into();
        }
    }

    fn open_picker(&mut self, purpose: PickerPurpose) {
        self.status = match purpose {
            PickerPurpose::Target => "pick the file to analyze".into(),
            PickerPurpose::CompareWith => "pick the file to compare with".into(),
        };

        // Variants of a sample usually sit next to it, so the compare picker starts there
        // instead of in the working directory.
        let picker = match (purpose, self.target.as_ref().and_then(|t| t.parent())) {
            (PickerPurpose::CompareWith, Some(dir)) => {
                Box::new(FilePicker::in_dir(dir.to_path_buf()))
            }
            _ => Box::default(),
        };
        self.mode = Mode::FilePicker { picker, purpose };
    }

    fn open_hex(&mut self, offset: u64) {
        let Some(target) = self.target.clone() else {
            self.status = "no target file: press @ to choose one".into();
            return;
        };
        match HexView::open(target, offset) {
            Ok(v) => self.mode = Mode::Hex(Box::new(v)),
            Err(e) => self.status = e,
        }
    }

    fn open_triage(&mut self) {
        if self.triage_job.is_some() {
            self.status = "triage already running".into();
            return;
        }
        let dir = self
            .target
            .as_ref()
            .and_then(|t| t.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| self.out_dir());
        let (tx, rx) = channel();
        let scan_dir = dir.clone();
        std::thread::spawn(move || {
            let _ = tx.send(triage::scan(&scan_dir, false, 200));
        });
        self.status = format!("triaging {}...", dir.display());
        self.triage_job = Some((dir, rx));
    }

    fn handle_value_input(&mut self, key: KeyEvent, step: usize, opt: usize, mut buffer: String) {
        match key.code {
            KeyCode::Esc => self.status = "cancelled".into(),
            KeyCode::Enter => {
                let value = buffer.trim().to_string();
                if value.is_empty() {
                    self.status = "empty value: option left unchecked".into();
                } else {
                    self.values[step][opt] = value;
                    self.checked[step][opt] = true;
                    self.refresh_preview();
                }
            }
            KeyCode::Backspace => {
                buffer.pop();
                self.mode = Mode::ValueInput { step, opt, buffer };
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                buffer.clear();
                self.mode = Mode::ValueInput { step, opt, buffer };
            }
            KeyCode::Char(c) => {
                buffer.push(c);
                self.mode = Mode::ValueInput { step, opt, buffer };
            }
            _ => self.mode = Mode::ValueInput { step, opt, buffer },
        }
    }

    fn handle_picker(
        &mut self,
        key: KeyEvent,
        mut picker: Box<FilePicker>,
        purpose: PickerPurpose,
    ) {
        match key.code {
            KeyCode::Esc => {}
            KeyCode::Enter => match picker.selected_path() {
                Some(path) => match purpose {
                    PickerPurpose::Target => self.set_target(path),
                    PickerPurpose::CompareWith => {
                        let path = std::fs::canonicalize(&path).unwrap_or(path);
                        self.values[STEP_COMPARE][0] = path.display().to_string();
                        self.checked[STEP_COMPARE][0] = true;
                        self.select_step(STEP_COMPARE);
                        self.run_current();
                    }
                },
                None => {
                    self.status = "no file selected".into();
                    self.mode = Mode::FilePicker { picker, purpose };
                }
            },
            KeyCode::Up => {
                picker.up();
                self.mode = Mode::FilePicker { picker, purpose };
            }
            KeyCode::Down | KeyCode::Tab => {
                picker.down();
                self.mode = Mode::FilePicker { picker, purpose };
            }
            KeyCode::Backspace => {
                picker.pop();
                self.mode = Mode::FilePicker { picker, purpose };
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                picker.clear();
                self.mode = Mode::FilePicker { picker, purpose };
            }
            KeyCode::Char(c) => {
                picker.push(c);
                self.mode = Mode::FilePicker { picker, purpose };
            }
            _ => self.mode = Mode::FilePicker { picker, purpose },
        }
    }

    fn handle_doctor(&mut self, key: KeyEvent, doctor: Box<Doctor>, mut selected: usize) {
        let n = doctor.tools.len();
        match key.code {
            KeyCode::Esc | KeyCode::Char('i') | KeyCode::Char('q') => return,
            KeyCode::Up => selected = (selected + n - 1) % n,
            KeyCode::Down | KeyCode::Tab => selected = (selected + 1) % n,
            KeyCode::Enter => {
                let tool = &doctor.tools[selected];
                if tool.installed() {
                    self.status = format!("{} is already installed", tool.def.name);
                } else {
                    match &tool.install {
                        Some(cmd) => {
                            self.pending = Some(PendingAction::Shell(cmd.clone()));
                            return;
                        }
                        None => {
                            self.status =
                                format!("no known way to install {} on this system", tool.def.name)
                        }
                    }
                }
            }
            KeyCode::Char('a') | KeyCode::Char('A') => match doctor.install_all_command() {
                Some(cmd) => {
                    self.pending = Some(PendingAction::Shell(cmd));
                    return;
                }
                None => {
                    self.status = if doctor.missing().is_empty() {
                        "nothing to install".into()
                    } else {
                        "no package manager detected".into()
                    }
                }
            },
            _ => {}
        }
        self.mode = Mode::Doctor { doctor, selected };
    }

    fn handle_presets(&mut self, key: KeyEvent, mut selected: usize) {
        let n = self.presets.len().max(1);
        match key.code {
            KeyCode::Esc | KeyCode::Char('p') | KeyCode::Char('q') => return,
            KeyCode::Up => selected = (selected + n - 1) % n,
            KeyCode::Down | KeyCode::Tab => selected = (selected + 1) % n,
            KeyCode::Enter => {
                if let Some(p) = self.presets.get(selected).cloned() {
                    self.apply_preset(&p);
                }
                return;
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                if let Some(p) = self.presets.get(selected).cloned() {
                    self.apply_preset(&p);
                    self.run_all_checked();
                }
                return;
            }
            _ => {}
        }
        self.mode = Mode::Presets { selected };
    }

    fn handle_search(&mut self, key: KeyEvent, mut buffer: String) {
        match key.code {
            KeyCode::Esc => {}
            KeyCode::Enter => {
                self.search = Some(buffer).filter(|b| !b.is_empty());
                self.jump_search(true);
            }
            KeyCode::Backspace => {
                buffer.pop();
                self.mode = Mode::Search { buffer };
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                buffer.clear();
                self.mode = Mode::Search { buffer };
            }
            KeyCode::Char(c) => {
                buffer.push(c);
                self.mode = Mode::Search { buffer };
            }
            _ => self.mode = Mode::Search { buffer },
        }
    }

    fn jump_search(&mut self, forward: bool) {
        let Some(needle) = self.search.clone() else {
            self.status = "no search: press / first".into();
            return;
        };
        let Some(result) = &self.results[self.selected] else {
            return;
        };
        let needle_l = needle.to_lowercase();
        let width = self.output_width.get().max(1) as usize;

        // Paragraph scrolls in wrapped rows, not logical lines: the jump has to account
        // for every earlier line that wrapped.
        let mut row_of_line = Vec::new();
        let mut row = 0usize;
        for line in result.output.lines() {
            row_of_line.push(row);
            row += line.chars().count().div_ceil(width).max(1);
        }
        let lines: Vec<&str> = result.output.lines().collect();
        let matches: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.to_lowercase().contains(&needle_l))
            .map(|(i, _)| i)
            .collect();
        if matches.is_empty() {
            self.status = format!("\"{needle}\" not found");
            return;
        }
        let current = self.output_scroll as usize;
        let target = if forward {
            matches
                .iter()
                .copied()
                .find(|i| row_of_line[*i] > current)
                .or_else(|| matches.first().copied())
        } else {
            matches
                .iter()
                .rev()
                .copied()
                .find(|i| row_of_line[*i] < current)
                .or_else(|| matches.last().copied())
        };
        if let Some(i) = target {
            self.output_scroll = row_of_line[i] as u16;
            let pos = matches.iter().position(|m| *m == i).unwrap_or(0) + 1;
            self.status = format!(
                "\"{needle}\": match {pos}/{} (n next, N previous)",
                matches.len()
            );
        }
    }

    fn handle_hex(&mut self, key: KeyEvent, mut view: Box<HexView>) {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('x') => return,
            KeyCode::Up => view.move_by(-16),
            KeyCode::Down => view.move_by(16),
            KeyCode::Left => view.move_by(-1),
            KeyCode::Right => view.move_by(1),
            KeyCode::PageUp => view.move_by(-view.page()),
            KeyCode::PageDown => view.move_by(view.page()),
            KeyCode::Home => view.goto(0),
            KeyCode::End => view.goto(view.len.saturating_sub(1)),
            KeyCode::Char('g') | KeyCode::Char('G') => {
                self.mode = Mode::HexGoto {
                    view,
                    buffer: String::new(),
                };
                return;
            }
            _ => {}
        }
        self.mode = Mode::Hex(view);
    }

    fn handle_hex_goto(&mut self, key: KeyEvent, mut view: Box<HexView>, mut buffer: String) {
        match key.code {
            KeyCode::Esc => self.mode = Mode::Hex(view),
            KeyCode::Enter => {
                match crate::hex::parse_offset(&buffer) {
                    Some(off) => view.goto(off),
                    None => {
                        self.status = format!("invalid offset \"{buffer}\" (use 0x1a2b or decimal)")
                    }
                }
                self.mode = Mode::Hex(view);
            }
            KeyCode::Backspace => {
                buffer.pop();
                self.mode = Mode::HexGoto { view, buffer };
            }
            KeyCode::Char(c) => {
                buffer.push(c);
                self.mode = Mode::HexGoto { view, buffer };
            }
            _ => self.mode = Mode::HexGoto { view, buffer },
        }
    }

    fn handle_triage(
        &mut self,
        key: KeyEvent,
        dir: PathBuf,
        rows: Vec<triage::Row>,
        mut selected: usize,
    ) {
        let n = rows.len().max(1);
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('t') => return,
            KeyCode::Up => selected = (selected + n - 1) % n,
            KeyCode::Down | KeyCode::Tab => selected = (selected + 1) % n,
            KeyCode::Enter => {
                if let Some(row) = rows.get(selected) {
                    self.set_target(row.path.clone());
                }
                return;
            }
            _ => {}
        }
        self.mode = Mode::Triage {
            dir,
            rows,
            selected,
        };
    }

    pub fn set_target(&mut self, path: PathBuf) {
        let path = std::fs::canonicalize(&path).unwrap_or(path);
        self.status = format!("target: {}", path.display());

        if self.target.as_ref() != Some(&path) {
            self.results = vec![None; STEPS.len()];
            if self.focus == Focus::Output {
                self.focus = Focus::Options;
            }
        }
        self.target = Some(path);
        self.refresh_preview();
    }

    fn open_in_editor(&mut self) {
        let Some(result) = &self.results[self.selected] else {
            self.status = "nothing to open".into();
            return;
        };

        let written = result
            .output
            .lines()
            .find_map(|l| l.strip_prefix("written: "))
            .map(PathBuf::from);
        let path = match written {
            Some(p) if p.is_file() => p,
            _ => {
                let p = std::env::temp_dir().join(format!(
                    "binscout-{}.txt",
                    STEPS[self.selected].name.replace([' ', '/'], "_")
                ));
                if let Err(e) = std::fs::write(&p, &result.output) {
                    self.status = format!("cannot write {}: {e}", p.display());
                    return;
                }
                p
            }
        };
        self.pending = Some(PendingAction::Editor(path));
    }

    fn copy_output(&mut self) {
        let Some(result) = &self.results[self.selected] else {
            self.status = "nothing to copy".into();
            return;
        };
        let candidates: [(&str, &[&str]); 4] = [
            ("wl-copy", &[]),
            ("xclip", &["-selection", "clipboard"]),
            ("xsel", &["--clipboard", "--input"]),
            ("pbcopy", &[]),
        ];
        for (tool, args) in candidates {
            if !tool_available(tool) {
                continue;
            }
            let child = std::process::Command::new(tool)
                .args(args)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
            if let Ok(mut child) = child {
                if let Some(mut stdin) = child.stdin.take() {
                    use std::io::Write;
                    let _ = stdin.write_all(result.output.as_bytes());
                }
                let _ = child.wait();
                self.status = format!("output copied to the clipboard ({tool})");
                return;
            }
        }
        self.status = "no clipboard tool found (wl-copy, xclip, xsel or pbcopy)".into();
    }

    fn run_current(&mut self) {
        let step = self.selected;
        if self.running.is_some() {
            self.queue.push_back(step);
            self.status = format!("queued: {}", STEPS[step].title);
            return;
        }
        self.start(step);
    }

    fn run_all_checked(&mut self) {
        let mut steps: Vec<usize> = (0..STEPS.len())
            .filter(|s| *s != STEP_REPORT && self.checked[*s].iter().any(|c| *c))
            .collect();
        // The report always goes last so it sees every other result of this run.
        if self.checked[STEP_REPORT].iter().any(|c| *c) {
            steps.push(STEP_REPORT);
        }
        if steps.is_empty() {
            self.status =
                "nothing checked: tick options, pick a preset (p), or press Space to run one step"
                    .into();
            return;
        }
        self.queue.extend(steps);
        if self.running.is_none()
            && let Some(next) = self.queue.pop_front()
        {
            self.start(next);
        }
    }

    fn start(&mut self, step: usize) {
        let Some(target) = self.target.clone() else {
            self.status = "no target file: press @ to choose one".into();
            self.queue.clear();
            return;
        };
        let req = StepRequest {
            step,
            target,
            checked: self.checked[step].clone(),
            values: self.values[step].clone(),
            previous: self.results.clone(),
            out_dir: self.out_dir(),
        };
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            set_progress(Some(tx.clone()));
            let result = run_step(req);
            set_progress(None);
            let _ = tx.send(Message::Done(result));
        });
        self.running = Some(Running {
            step,
            started: Instant::now(),
            rx,
        });
        self.results[step] = None;
        self.live.clear();
        self.status = format!("running {}...", STEPS[step].title);
        if step == self.selected {
            self.focus = Focus::Output;
            self.output_scroll = 0;
        }
    }

    pub fn poll_worker(&mut self) {
        if let Some((dir, rx)) = &self.triage_job {
            match rx.try_recv() {
                Ok(rows) => {
                    let dir = dir.clone();
                    self.triage_job = None;
                    if rows.is_empty() {
                        self.status = format!("no file to triage in {}", dir.display());
                    } else {
                        self.status = format!(
                            "{} file(s) triaged in {}: Enter picks one as the target",
                            rows.len(),
                            dir.display()
                        );
                        self.mode = Mode::Triage {
                            dir,
                            rows,
                            selected: 0,
                        };
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.triage_job = None;
                    self.status = "triage failed".into();
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        let Some(running) = &self.running else { return };
        loop {
            match running.rx.try_recv() {
                Ok(Message::Line(l)) => {
                    self.live.push(l);
                    // Capped: binwalk -A can print hundreds of thousands of lines; the full output
                    // is kept in the result anyway.
                    if self.live.len() > 5000 {
                        self.live.drain(..1000);
                    }
                }
                Ok(Message::Done(result)) => {
                    let step = running.step;
                    self.status = format!(
                        "{}: {:?} in {} ms",
                        STEPS[step].title, result.status, result.duration_ms
                    )
                    .to_lowercase();
                    self.results[step] = Some(result);
                    self.running = None;
                    self.live.clear();
                    if let Some(next) = self.queue.pop_front() {
                        self.start(next);
                    }
                    return;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    let step = running.step;
                    self.results[step] = Some(StepResult::failed(step, "worker thread panicked"));
                    self.running = None;
                    self.live.clear();
                    self.queue.clear();
                    return;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => return,
            }
        }
    }
}

fn detect_missing_tools() -> HashSet<&'static str> {
    let mut missing = HashSet::new();
    for step in STEPS {
        for tool in step
            .tool
            .into_iter()
            .chain(step.options.iter().filter_map(|o| o.tool))
        {
            if !tool_available(tool) {
                missing.insert(tool);
            }
        }
    }
    missing
}
