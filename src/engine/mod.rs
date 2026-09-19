pub mod runner;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    Ok,

    Failed,

    Skipped,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RawOutput {
    pub command: String,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub step: usize,
    pub name: String,
    pub status: Status,

    pub output: String,

    #[serde(default)]
    pub raw: Vec<RawOutput>,
    pub duration_ms: u128,

    #[serde(default)]
    pub options: Vec<String>,
}

impl StepResult {
    pub fn new(step: usize) -> Self {
        Self {
            step,
            name: crate::catalog::step(step).title.to_string(),
            status: Status::Ok,
            output: String::new(),
            raw: Vec::new(),
            duration_ms: 0,
            options: Vec::new(),
        }
    }

    pub fn skipped(step: usize, reason: impl Into<String>) -> Self {
        let mut r = Self::new(step);
        r.status = Status::Skipped;
        r.output = reason.into();
        r
    }

    pub fn failed(step: usize, reason: impl Into<String>) -> Self {
        let mut r = Self::new(step);
        r.status = Status::Failed;
        r.output = reason.into();
        r
    }

    pub fn push_line(&mut self, line: impl AsRef<str>) {
        // Tabs are expanded here once: terminals render them unpredictably inside a bordered pane.
        self.output.push_str(&line.as_ref().replace('\t', "    "));
        self.output.push('\n');
    }
}

#[derive(Debug)]
pub enum Message {
    Line(String),
    Done(StepResult),
}

#[derive(Debug, Clone)]
pub struct StepRequest {
    pub step: usize,
    pub target: PathBuf,
    pub checked: Vec<bool>,
    pub values: Vec<String>,

    pub previous: Vec<Option<StepResult>>,

    pub out_dir: PathBuf,
}

impl StepRequest {
    pub fn is_checked(&self, opt: usize) -> bool {
        self.checked.get(opt).copied().unwrap_or(false)
    }

    pub fn value(&self, opt: usize) -> &str {
        self.values.get(opt).map(String::as_str).unwrap_or("")
    }

    pub fn any_checked(&self) -> bool {
        self.checked.iter().any(|c| *c)
    }

    pub fn checked_labels(&self) -> Vec<String> {
        let step = crate::catalog::step(self.step);
        step.options
            .iter()
            .enumerate()
            .filter(|(i, _)| self.is_checked(*i))
            .map(|(i, o)| {
                let v = self.value(i);
                if v.is_empty() {
                    o.label.to_string()
                } else {
                    format!("{} = {}", o.label, v)
                }
            })
            .collect()
    }
}
