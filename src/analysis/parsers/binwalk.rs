#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub offset: u64,
    pub description: String,
}

pub fn parse(stdout: &str) -> Vec<Signature> {
    stdout
        .lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let offset = it.next()?.parse::<u64>().ok()?;
            let hex = it.next()?;
            if !hex.starts_with("0x") {
                return None;
            }
            let description = it.collect::<Vec<_>>().join(" ");
            if description.is_empty() {
                return None;
            }
            Some(Signature {
                offset,
                description,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_table() {
        let out = "\nDECIMAL       HEXADECIMAL     DESCRIPTION\n\
                   --------------------------------------------------------------------------------\n\
                   0             0x0             ELF, 64-bit LSB shared object, AMD x86-64, version 1 (SYSV)\n\
                   1024          0x400           gzip compressed data\n";
        let sigs = parse(out);
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[1].offset, 1024);
        assert_eq!(sigs[1].description, "gzip compressed data");
    }
}
