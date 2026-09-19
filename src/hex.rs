use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

pub const BYTES_PER_ROW: u64 = 16;

pub struct HexView {
    pub path: PathBuf,
    pub len: u64,

    pub offset: u64,

    pub cursor: u64,
    pub rows: usize,
}

impl HexView {
    pub fn open(path: PathBuf, offset: u64) -> Result<Self, String> {
        let len = std::fs::metadata(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .len();
        let cursor = offset.min(len.saturating_sub(1));
        Ok(Self {
            path,
            len,
            offset: cursor - cursor % BYTES_PER_ROW,
            cursor,
            rows: 16,
        })
    }

    // Only the visible window is read: the viewer must open multi-GB files instantly.
    pub fn read_window(&self) -> Vec<u8> {
        let mut f = match File::open(&self.path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        if f.seek(SeekFrom::Start(self.offset)).is_err() {
            return Vec::new();
        }
        let mut buf = vec![0u8; (self.rows as u64 * BYTES_PER_ROW) as usize];
        let mut total = 0;
        while total < buf.len() {
            match f.read(&mut buf[total..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => total += n,
            }
        }
        buf.truncate(total);
        buf
    }

    fn clamp(&mut self) {
        self.cursor = self.cursor.min(self.len.saturating_sub(1));
        let window = self.rows as u64 * BYTES_PER_ROW;
        if self.cursor < self.offset {
            self.offset = self.cursor - self.cursor % BYTES_PER_ROW;
        } else if self.cursor >= self.offset + window {
            self.offset = self.cursor - self.cursor % BYTES_PER_ROW + BYTES_PER_ROW - window;
        }
    }

    pub fn move_by(&mut self, delta: i64) {
        self.cursor =
            (self.cursor as i64 + delta).clamp(0, self.len.saturating_sub(1) as i64) as u64;
        self.clamp();
    }

    pub fn goto(&mut self, offset: u64) {
        self.cursor = offset.min(self.len.saturating_sub(1));
        self.offset = self.cursor - self.cursor % BYTES_PER_ROW;
    }

    pub fn page(&self) -> i64 {
        self.rows as i64 * BYTES_PER_ROW as i64
    }
}

pub fn parse_offset(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(h) = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .or_else(|| t.strip_prefix('$'))
    {
        return u64::from_str_radix(h, 16).ok();
    }
    if let Some(h) = t.strip_suffix('h').or_else(|| t.strip_suffix('H')) {
        return u64::from_str_radix(h, 16).ok();
    }
    t.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_offsets() {
        assert_eq!(parse_offset("0x10"), Some(16));
        assert_eq!(parse_offset("16"), Some(16));
        assert_eq!(parse_offset("10h"), Some(16));
        assert_eq!(parse_offset("zz"), None);
    }
}
