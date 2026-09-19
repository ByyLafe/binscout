use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config, Matcher};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const MAX_ENTRIES: usize = 60_000;
const MAX_RESULTS: usize = 300;
const RELATIVE_DEPTH: usize = 10;
const ABSOLUTE_DEPTH: usize = 5;

const SKIP_DIRS: &[&str] = &[
    "target",
    "node_modules",
    "__pycache__",
    ".git",
    "proc",
    "sys",
    "dev",
    "run",
    "snap",
];

pub struct FilePicker {
    pub query: String,
    pub selected: usize,

    pub results: Vec<String>,
    pub root: PathBuf,
    pub truncated: bool,

    base: PathBuf,
    entries: Vec<String>,
    matcher: Matcher,
}

impl FilePicker {
    pub fn new() -> Self {
        Self::in_dir(std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
    }

    pub fn in_dir(base: PathBuf) -> Self {
        let mut p = Self {
            query: String::new(),
            selected: 0,
            results: Vec::new(),
            root: PathBuf::new(),
            truncated: false,
            base: base.clone(),
            entries: Vec::new(),
            matcher: Matcher::new(Config::DEFAULT.match_paths()),
        };
        p.set_root(base, RELATIVE_DEPTH);
        p.refresh("");
        p
    }

    pub fn push(&mut self, c: char) {
        self.query.push(c);
        self.on_query_changed();
    }

    pub fn pop(&mut self) {
        self.query.pop();
        self.on_query_changed();
    }

    pub fn clear(&mut self) {
        self.query.clear();
        self.on_query_changed();
    }

    pub fn up(&mut self) {
        if !self.results.is_empty() {
            self.selected = if self.selected == 0 {
                self.results.len() - 1
            } else {
                self.selected - 1
            };
        }
    }

    pub fn down(&mut self) {
        if !self.results.is_empty() {
            self.selected = (self.selected + 1) % self.results.len();
        }
    }

    pub fn is_absolute(&self) -> bool {
        self.query.starts_with('/') || self.query.starts_with('~')
    }

    pub fn selected_path(&self) -> Option<PathBuf> {
        if let Some(rel) = self.results.get(self.selected) {
            return Some(self.root.join(rel));
        }
        // A pasted path to an existing file is accepted even when it is not indexed
        // (hidden directory, depth or entry cap).
        let typed = crate::engine::runner::expand_tilde(&self.query);
        typed.is_file().then_some(typed)
    }

    pub fn display(&self, rel: &str) -> String {
        if self.is_absolute() {
            self.root.join(rel).display().to_string()
        } else {
            rel.to_string()
        }
    }

    fn on_query_changed(&mut self) {
        let (root, needle, depth) = if self.is_absolute() {
            let expanded = crate::engine::runner::expand_tilde(&self.query)
                .display()
                .to_string();

            let (dir, rest) = match expanded.rfind('/') {
                Some(i) => (expanded[..=i].to_string(), expanded[i + 1..].to_string()),
                None => ("/".to_string(), expanded.clone()),
            };
            let dir = PathBuf::from(if dir.is_empty() { "/" } else { &dir });
            if dir.is_dir() {
                (dir, rest, ABSOLUTE_DEPTH)
            } else {
                (self.root.clone(), rest, ABSOLUTE_DEPTH)
            }
        } else {
            (self.base.clone(), self.query.clone(), RELATIVE_DEPTH)
        };
        if root != self.root {
            self.set_root(root, depth);
        }
        self.refresh(&needle);
    }

    fn set_root(&mut self, root: PathBuf, depth: usize) {
        self.entries.clear();
        self.truncated = false;
        let walker = WalkDir::new(&root)
            .max_depth(depth)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();

                // The root itself may be hidden (~/.config): only children are filtered.
                e.depth() == 0 || !(name.starts_with('.') || SKIP_DIRS.contains(&name.as_ref()))
            });
        for entry in walker.filter_map(Result::ok) {
            if !entry.file_type().is_file() {
                continue;
            }
            if self.entries.len() >= MAX_ENTRIES {
                self.truncated = true;
                break;
            }
            if let Ok(rel) = entry.path().strip_prefix(&root) {
                self.entries.push(rel.to_string_lossy().into_owned());
            }
        }
        self.entries.sort();
        self.root = root;
    }

    fn refresh(&mut self, needle: &str) {
        self.selected = 0;
        if needle.trim().is_empty() {
            self.results = self.entries.iter().take(MAX_RESULTS).cloned().collect();
            return;
        }
        let pattern = Pattern::parse(needle, CaseMatching::Ignore, Normalization::Smart);
        let matches =
            pattern.match_list(self.entries.iter().map(String::as_str), &mut self.matcher);
        self.results = matches
            .into_iter()
            .take(MAX_RESULTS)
            .map(|(s, _)| s.to_string())
            .collect();
    }
}

impl Default for FilePicker {
    fn default() -> Self {
        Self::new()
    }
}

pub fn pretty_path(path: &Path, max: usize) -> String {
    let mut s = path.display().to_string();
    if let Some(home) = dirs::home_dir()
        && let Ok(rest) = path.strip_prefix(&home)
    {
        s = format!("~/{}", rest.display());
    }
    if s.chars().count() <= max || max < 8 {
        return s;
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let keep_tail = name.chars().count().min(max.saturating_sub(4));
    let chars: Vec<char> = s.chars().collect();
    let tail: String = chars[chars.len() - keep_tail..].iter().collect();
    let head: String = chars
        .iter()
        .take(max.saturating_sub(keep_tail + 1))
        .collect();
    format!("{head}\u{2026}{tail}")
}
