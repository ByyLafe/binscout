use crate::catalog::{OptionKind, STEPS};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::OnceLock;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub vt_api_key: Option<String>,
    pub bazaar_api_key: Option<String>,
    pub yara_rules: Option<String>,
    pub editor: Option<String>,
    pub default_preset: Option<String>,

    pub presets: BTreeMap<String, BTreeMap<String, Vec<String>>>,

    #[serde(skip)]
    pub path: Option<PathBuf>,
    #[serde(skip)]
    pub load_error: Option<String>,
}

static CONFIG: OnceLock<Config> = OnceLock::new();

pub fn config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("binscout").join("config.toml"))
}

pub fn get() -> &'static Config {
    CONFIG.get_or_init(Config::load)
}

impl Config {
    pub fn load() -> Self {
        let Some(path) = config_path() else {
            return Self::default();
        };
        let mut cfg = match std::fs::read_to_string(&path) {
            Ok(text) => match toml::from_str::<Config>(&text) {
                Ok(c) => c,
                Err(e) => Config {
                    load_error: Some(format!("{}: {e}", path.display())),
                    ..Default::default()
                },
            },
            Err(_) => Config::default(),
        };
        cfg.path = Some(path);
        cfg
    }

    pub fn vt_api_key(&self) -> Option<String> {
        self.vt_api_key
            .clone()
            .filter(|k| !k.trim().is_empty())
            .or_else(|| std::env::var("VT_API_KEY").ok())
            .filter(|k| !k.trim().is_empty())
    }

    pub fn bazaar_api_key(&self) -> Option<String> {
        self.bazaar_api_key
            .clone()
            .filter(|k| !k.trim().is_empty())
            .or_else(|| std::env::var("MALWAREBAZAAR_API_KEY").ok())
            .filter(|k| !k.trim().is_empty())
    }

    pub fn editor(&self) -> String {
        self.editor
            .clone()
            .filter(|e| !e.trim().is_empty())
            .or_else(|| std::env::var("VISUAL").ok())
            .or_else(|| std::env::var("EDITOR").ok())
            .filter(|e| !e.trim().is_empty())
            .unwrap_or_else(|| "vi".to_string())
    }

    pub fn presets(&self) -> Vec<Preset> {
        let mut all = builtin_presets();
        for (name, steps) in &self.presets {
            let preset = Preset::from_labels(name, "from config.toml", steps);
            all.retain(|p| p.name != *name);
            all.push(preset);
        }
        all
    }

    pub fn preset(&self, name: &str) -> Option<Preset> {
        self.presets()
            .into_iter()
            .find(|p| p.name.eq_ignore_ascii_case(name))
    }
}

#[derive(Debug, Clone)]
pub struct Preset {
    pub name: String,
    pub description: String,
    pub checked: Vec<Vec<bool>>,
    pub values: Vec<Vec<Option<String>>>,

    pub unknown: Vec<String>,
}

impl Preset {
    fn empty(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            checked: STEPS.iter().map(|s| vec![false; s.options.len()]).collect(),
            values: STEPS.iter().map(|s| vec![None; s.options.len()]).collect(),
            unknown: Vec::new(),
        }
    }

    fn set(&mut self, step_name: &str, spec: &str) {
        let (label, value) = match spec.split_once('=') {
            Some((l, v)) => (l.trim(), Some(v.trim().to_string())),
            None => (spec.trim(), None),
        };
        let Some(step) = STEPS
            .iter()
            .position(|s| s.name.eq_ignore_ascii_case(step_name))
        else {
            self.unknown.push(format!("{step_name}: unknown step"));
            return;
        };
        // Presets name options by label prefix rather than index so a config file survives
        // options being reordered or inserted.
        let opt = STEPS[step]
            .options
            .iter()
            .position(|o| o.label.to_lowercase().starts_with(&label.to_lowercase()));
        match opt {
            Some(i) => {
                self.checked[step][i] = true;
                if value.is_some() {
                    self.values[step][i] = value;
                }
            }
            None => self
                .unknown
                .push(format!("{step_name}: no option starting with \"{label}\"")),
        }
    }

    fn set_all(&mut self, step_name: &str, specs: &[&str]) {
        for s in specs {
            self.set(step_name, s);
        }
    }

    fn from_labels(name: &str, description: &str, steps: &BTreeMap<String, Vec<String>>) -> Self {
        let mut p = Self::empty(name, description);
        for (step, labels) in steps {
            for l in labels {
                p.set(step, l);
            }
        }
        p
    }

    fn set_all_flags(&mut self, step_name: &str) {
        if let Some(step) = STEPS
            .iter()
            .position(|s| s.name.eq_ignore_ascii_case(step_name))
        {
            for (i, o) in STEPS[step].options.iter().enumerate() {
                if matches!(o.kind, OptionKind::Flag) && o.tool.is_none() {
                    self.checked[step][i] = true;
                }
            }
        }
    }
}

pub fn builtin_presets() -> Vec<Preset> {
    let mut quick = Preset::empty(
        "quick",
        "offline triage in a few seconds, native steps only",
    );
    quick.set_all("file", &["List all"]);
    quick.set_all("hashes", &["sha256", "md5", "sha1", "Imphash"]);
    quick.set_all(
        "packer",
        &["Known packer", "Compiler", "Packing heuristics"],
    );
    quick.set_all("entropy", &["Overall", "Entropy per section"]);
    quick.set_all_flags("mitigations");
    quick.set_all_flags("anti-analysis");
    quick.set_all_flags("iocs");
    quick.set_all("final report", &["Markdown", "Mention"]);

    let mut full = Preset::empty(
        "full",
        "everything that runs offline, external tools included",
    );
    for step in STEPS {
        full.set_all_flags(step.name);
    }
    full.set_all("hashes", &["Fuzzy hash"]);
    full.set_all("container", &["List"]);
    full.set_all(
        "binwalk",
        &[
            "Search for known file signatures",
            "Search for executable",
            "Run an entropy",
        ],
    );
    full.set_all("entropy", &["Sliding window", "Custom alert"]);
    full.set_all("strings / floss", &["Minimum strings length", "Decoded"]);
    full.set_all("yara", &["Default community rules"]);
    full.set_all("disasm", &["Disassemble around", "Intel", "Function list"]);
    full.set_all("compare", &["ssdeep"]);

    full.set_all(
        "final report",
        &["Markdown", "JSON", "Include raw", "Mention"],
    );
    uncheck(&mut full, "packer", "Unpack");
    uncheck(&mut full, "container", "Extract");
    uncheck(&mut full, "binwalk", "Automatically extract");
    uncheck(&mut full, "disasm", "Full disassembly");

    let mut online = quick.clone();
    online.name = "online".into();
    online.description = "quick triage plus VirusTotal and MalwareBazaar lookups".into();
    online.set_all("hashes", &["Check online", "Check MalwareBazaar"]);

    vec![quick, full, online]
}

fn uncheck(p: &mut Preset, step_name: &str, label: &str) {
    if let Some(step) = STEPS.iter().position(|s| s.name == step_name) {
        for (i, o) in STEPS[step].options.iter().enumerate() {
            if o.label.starts_with(label) {
                p.checked[step][i] = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{STEP_HASHES, STEP_PACKER, STEP_STRINGS};

    #[test]
    fn builtin_presets_resolve_every_label() {
        for p in builtin_presets() {
            assert!(p.unknown.is_empty(), "{}: {:?}", p.name, p.unknown);
        }
    }

    #[test]
    fn preset_from_config_sets_values() {
        let mut steps = BTreeMap::new();
        steps.insert(
            "strings / floss".to_string(),
            vec!["Minimum strings length=8".to_string()],
        );
        steps.insert(
            "hashes".to_string(),
            vec!["sha256".to_string(), "nope".to_string()],
        );
        let p = Preset::from_labels("t", "", &steps);
        assert!(p.checked[STEP_STRINGS][2]);
        assert_eq!(p.values[STEP_STRINGS][2].as_deref(), Some("8"));
        assert!(p.checked[STEP_HASHES][0]);
        assert_eq!(p.unknown.len(), 1);
        assert!(!p.checked[STEP_PACKER][3]);
    }
}
