#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInfo {
    pub path: String,
    pub description: String,

    pub attributes: Vec<String>,
}

impl FileInfo {
    pub fn summary(&self) -> String {
        let mut s = format!("type: {}", self.description);
        if !self.attributes.is_empty() {
            s.push_str(&format!("\nattributes: {}", self.attributes.join(" | ")));
        }
        s
    }
}

pub fn parse(stdout: &str) -> Option<FileInfo> {
    let line = stdout.lines().find(|l| !l.trim().is_empty())?;
    let (path, rest) = line.split_once(": ")?;
    let mut parts = rest.split(", ").map(str::trim).filter(|p| !p.is_empty());
    let description = parts.next()?.to_string();
    Some(FileInfo {
        path: path.trim().to_string(),
        description,
        attributes: parts.map(String::from).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_elf_line() {
        let info =
            parse("/bin/ls: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), stripped\n")
                .unwrap();
        assert_eq!(info.path, "/bin/ls");
        assert_eq!(info.description, "ELF 64-bit LSB pie executable");
        assert_eq!(
            info.attributes,
            vec!["x86-64", "version 1 (SYSV)", "stripped"]
        );
    }
}
