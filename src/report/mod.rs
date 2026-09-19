use crate::catalog::{self, STEP_REPORT, STEPS};
use crate::engine::{Status, StepRequest, StepResult};
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
pub struct Report<'a> {
    pub tool: &'static str,
    pub version: &'static str,
    pub generated_at: String,
    pub target: String,
    pub steps: Vec<&'a StepResult>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_run: Vec<&'static str>,
}

impl<'a> Report<'a> {
    pub fn build(target: &Path, results: &'a [Option<StepResult>], mention_skipped: bool) -> Self {
        let steps: Vec<&StepResult> = results
            .iter()
            .flatten()
            .filter(|r| r.step != STEP_REPORT)
            .collect();
        let not_run = if mention_skipped {
            STEPS
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != STEP_REPORT && results.get(*i).is_none_or(Option::is_none))
                .map(|(_, s)| s.title)
                .collect()
        } else {
            Vec::new()
        };
        Self {
            tool: "BinScout",
            version: env!("CARGO_PKG_VERSION"),
            generated_at: chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            target: target.display().to_string(),
            steps,
            not_run,
        }
    }

    pub fn to_json(&self, include_raw: bool) -> String {
        if include_raw {
            return serde_json::to_string_pretty(self).unwrap_or_default();
        }

        // Stripping through a Value avoids cloning every StepResult just to drop `raw`.
        let mut v = serde_json::to_value(self).unwrap_or_default();
        if let Some(steps) = v.get_mut("steps").and_then(|s| s.as_array_mut()) {
            for s in steps {
                if let Some(obj) = s.as_object_mut() {
                    obj.remove("raw");
                }
            }
        }
        serde_json::to_string_pretty(&v).unwrap_or_default()
    }

    pub fn to_markdown(&self, include_raw: bool) -> String {
        let mut md = String::new();
        let name = Path::new(&self.target)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        md.push_str(&format!("# BinScout report \u{2014} `{name}`\n\n"));
        md.push_str(&format!("- **Target:** `{}`\n", self.target));
        md.push_str(&format!("- **Generated:** {}\n", self.generated_at));
        md.push_str(&format!("- **Tool:** {} {}\n\n", self.tool, self.version));

        md.push_str("## Summary\n\n| Step | Status | Duration |\n|------|--------|----------|\n");
        for s in &self.steps {
            md.push_str(&format!(
                "| {} | {} | {} ms |\n",
                s.name,
                status_label(&s.status),
                s.duration_ms
            ));
        }
        for title in &self.not_run {
            md.push_str(&format!("| {title} | not run | - |\n"));
        }
        md.push('\n');

        for s in &self.steps {
            md.push_str(&format!("## {}\n\n", s.name));
            md.push_str(&format!("**Status:** {}\n\n", status_label(&s.status)));
            if !s.options.is_empty() {
                md.push_str("**Options:**\n");
                for o in &s.options {
                    md.push_str(&format!("- {o}\n"));
                }
                md.push('\n');
            }
            let body = s.output.trim_end();
            if !body.is_empty() {
                md.push_str("```text\n");
                md.push_str(body);
                md.push_str("\n```\n\n");
            }
        }

        if !self.not_run.is_empty() {
            md.push_str("## Steps not run\n\n");
            for title in &self.not_run {
                md.push_str(&format!("- {title}\n"));
            }
            md.push('\n');
        }

        if include_raw {
            let with_raw: Vec<&&StepResult> =
                self.steps.iter().filter(|s| !s.raw.is_empty()).collect();
            if !with_raw.is_empty() {
                md.push_str("## Appendix: raw tool output\n\n");
                for s in with_raw {
                    for raw in &s.raw {
                        md.push_str(&format!("### {} \u{2014} `{}`\n\n", s.name, raw.command));
                        md.push_str(&format!(
                            "Exit code: {}\n\n",
                            raw.exit_code
                                .map(|c| c.to_string())
                                .unwrap_or_else(|| "n/a".into())
                        ));
                        if !raw.stdout.trim().is_empty() {
                            md.push_str("```text\n");
                            md.push_str(raw.stdout.trim_end());
                            md.push_str("\n```\n\n");
                        }
                        if !raw.stderr.trim().is_empty() {
                            md.push_str("stderr:\n\n```text\n");
                            md.push_str(raw.stderr.trim_end());
                            md.push_str("\n```\n\n");
                        }
                    }
                }
            }
        }
        md
    }
}

fn status_label(s: &Status) -> &'static str {
    match s {
        Status::Ok => "ok",
        Status::Failed => "failed",
        Status::Skipped => "skipped",
    }
}

pub fn output_path(out_dir: &Path, target: &Path, ext: &str) -> PathBuf {
    let stem = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "target".into());
    out_dir.join(format!("binscout-report-{stem}.{ext}"))
}

pub fn run(req: &StepRequest) -> StepResult {
    let mut result = StepResult::new(req.step);
    let markdown = req.is_checked(0) || !req.any_checked();
    let json = req.is_checked(1);
    let include_raw = req.is_checked(2);
    let mention_skipped = req.is_checked(3);

    let ran = req
        .previous
        .iter()
        .flatten()
        .filter(|r| r.step != STEP_REPORT)
        .count();
    if ran == 0 {
        return StepResult::skipped(
            req.step,
            "nothing to report yet: run at least one analysis step first (Space)",
        );
    }

    let report = Report::build(&req.target, &req.previous, mention_skipped);
    if crate::engine::runner::dry_run() {
        for ext in [("md", markdown), ("json", json)]
            .iter()
            .filter(|(_, on)| *on)
            .map(|(e, _)| *e)
        {
            result.push_line(format!(
                "would write {}",
                output_path(&req.out_dir, &req.target, ext).display()
            ));
        }
        return result;
    }
    let mut written = Vec::new();
    if markdown {
        let path = output_path(&req.out_dir, &req.target, "md");
        match std::fs::write(&path, report.to_markdown(include_raw)) {
            Ok(()) => written.push(path),
            Err(e) => {
                result.status = Status::Failed;
                result.push_line(format!("cannot write {}: {e}", path.display()));
            }
        }
    }
    if json {
        let path = output_path(&req.out_dir, &req.target, "json");
        match std::fs::write(&path, report.to_json(include_raw)) {
            Ok(()) => written.push(path),
            Err(e) => {
                result.status = Status::Failed;
                result.push_line(format!("cannot write {}: {e}", path.display()));
            }
        }
    }

    for p in &written {
        let abs = std::fs::canonicalize(p).unwrap_or_else(|_| p.clone());
        result.push_line(format!("written: {}", abs.display()));
    }
    result.push_line(format!(
        "{ran} step(s) included, {} not run",
        STEPS.len() - 1 - ran
    ));
    result.push_line("");
    result.push_line("---- preview ----");
    result.push_line(report.to_markdown(false));
    let _ = catalog::step(req.step);
    result
}

#[derive(Debug, serde::Deserialize)]
pub struct SavedReport {
    pub target: String,
    pub steps: Vec<StepResult>,
}

impl SavedReport {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        serde_json::from_str(&text)
            .map_err(|e| format!("{} is not a BinScout JSON report: {e}", path.display()))
    }

    pub fn into_results(self) -> (PathBuf, Vec<Option<StepResult>>) {
        let mut results: Vec<Option<StepResult>> = vec![None; STEPS.len()];
        for s in self.steps {
            let step = s.step;
            if STEPS.get(step).is_some_and(|def| def.title == s.name) {
                results[step] = Some(s);
            }
        }
        (PathBuf::from(self.target), results)
    }
}
