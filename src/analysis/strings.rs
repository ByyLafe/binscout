fn printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == b'\t'
}

pub fn ascii(data: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, b) in data.iter().enumerate() {
        match (printable(*b), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= min_len {
                    out.push(String::from_utf8_lossy(&data[s..i]).into_owned());
                }
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start
        && data.len() - s >= min_len
    {
        out.push(String::from_utf8_lossy(&data[s..]).into_owned());
    }
    out
}

pub fn utf16le(data: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let (lo, hi) = (data[i], data[i + 1]);
        if hi == 0 && printable(lo) {
            current.push(lo as char);
            i += 2;
        } else {
            if current.len() >= min_len {
                out.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
            // Advance one byte, not a pair: odd-aligned UTF-16 strings are common in PE resources.
            i += 1;
        }
    }
    if current.len() >= min_len {
        out.push(current);
    }
    out
}

pub fn all(data: &[u8], min_len: usize) -> Vec<String> {
    let mut v = ascii(data, min_len);
    v.extend(utf16le(data, min_len));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_both_encodings() {
        let mut data = b"\x00\x01hello world\x00\xff".to_vec();
        for c in "wide str".encode_utf16() {
            data.extend_from_slice(&c.to_le_bytes());
        }
        data.push(0);
        let s = all(&data, 4);
        assert_eq!(s, vec!["hello world".to_string(), "wide str".to_string()]);
    }
}
