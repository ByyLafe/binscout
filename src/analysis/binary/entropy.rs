use crate::analysis::{human_size, read_target, shannon_entropy};
use crate::engine::{Status, StepRequest, StepResult};

const GRAPH_WIDTH: usize = 64;
const BARS: [char; 8] = [
    '\u{2581}', '\u{2582}', '\u{2583}', '\u{2584}', '\u{2585}', '\u{2586}', '\u{2587}', '\u{2588}',
];

fn verdict(e: f64) -> &'static str {
    match e {
        e if e >= 7.5 => "very high: likely encrypted or compressed",
        e if e >= 7.0 => "high: compressed data or packed code",
        e if e >= 5.5 => "medium: typical machine code",
        e if e >= 3.0 => "low: text or sparse data",
        _ => "very low: padding or repeated bytes",
    }
}

fn bar(e: f64) -> char {
    let idx = ((e / 8.0) * (BARS.len() as f64 - 1.0)).round() as usize;
    BARS[idx.min(BARS.len() - 1)]
}

pub fn profile(data: &[u8], width: usize) -> Vec<f64> {
    if data.is_empty() || width == 0 {
        return Vec::new();
    }
    let chunk = data.len().div_ceil(width).max(1);
    data.chunks(chunk).map(shannon_entropy).collect()
}

pub fn ascii_graph(data: &[u8], threshold: f64) -> Vec<String> {
    let prof = profile(data, GRAPH_WIDTH);
    let line: String = prof.iter().map(|e| bar(*e)).collect();
    let alerts: String = prof
        .iter()
        .map(|e| if *e >= threshold { '^' } else { ' ' })
        .collect();
    let chunk = data.len().div_ceil(GRAPH_WIDTH).max(1);
    vec![
        format!("0x00000000 {line} 0x{:08X}", data.len()),
        format!("           {alerts}   (^ = above {threshold:.2})"),
        format!("           each column = {}", human_size(chunk as u64)),
    ]
}

pub fn high_regions(data: &[u8], window: usize, threshold: f64) -> Vec<(usize, usize, f64)> {
    let mut regions: Vec<(usize, usize, f64)> = Vec::new();
    for (i, chunk) in data.chunks(window).enumerate() {
        let e = shannon_entropy(chunk);
        if e < threshold {
            continue;
        }
        let start = i * window;
        let end = start + chunk.len();
        match regions.last_mut() {
            Some(last) if last.1 == start => {
                last.1 = end;
                last.2 = last.2.max(e);
            }
            _ => regions.push((start, end, e)),
        }
    }
    regions
}

pub fn run(req: &StepRequest) -> StepResult {
    let mut result = StepResult::new(req.step);
    let data = match read_target(&req.target) {
        Ok(d) => d,
        Err(e) => return StepResult::failed(req.step, e),
    };
    let none = !req.any_checked();

    let threshold = if req.is_checked(4) {
        match req.value(4).trim().parse::<f64>() {
            Ok(t) if (0.0..=8.0).contains(&t) => t,
            _ => {
                result.status = Status::Failed;
                result.push_line(format!(
                    "invalid threshold `{}` (expected 0-8), using 7.0",
                    req.value(4)
                ));
                7.0
            }
        }
    } else {
        7.0
    };

    if none || req.is_checked(1) {
        let e = shannon_entropy(&data);
        result.push_line(format!("overall entropy: {e:.4} / 8  ({})", verdict(e)));
        result.push_line(format!("file size: {}", human_size(data.len() as u64)));
        result.push_line("");
    }

    if req.is_checked(0) {
        match super::file_regions(&data) {
            Ok(regions) => {
                result.push_line(format!(
                    "{:<20} {:>10} {:>10}  {:>7}  {}",
                    "section", "offset", "size", "entropy", "verdict"
                ));
                for r in regions {
                    let end = r.offset.saturating_add(r.size).min(data.len());
                    if r.offset >= end {
                        continue;
                    }
                    let e = shannon_entropy(&data[r.offset..end]);
                    let flag = if e >= threshold { " !" } else { "" };
                    result.push_line(format!(
                        "{:<20} 0x{:08X} {:>10}  {:>7.3}  {}{flag}",
                        r.name,
                        r.offset,
                        human_size(r.size as u64),
                        e,
                        verdict(e)
                    ));
                }
                result.push_line("");
            }
            Err(e) => result.push_line(format!("per-section entropy unavailable: {e}\n")),
        }
    }

    if req.is_checked(2) {
        let window = match req.value(2).trim().parse::<usize>() {
            Ok(w) if w > 0 => w,
            _ => {
                result.push_line(format!("invalid window size `{}`, using 256", req.value(2)));
                256
            }
        };
        let regions = high_regions(&data, window, threshold);
        result.push_line(format!(
            "sliding window {} bytes, threshold {threshold:.2}: {} high-entropy region(s)",
            window,
            regions.len()
        ));
        for (start, end, max) in regions.iter().take(200) {
            result.push_line(format!(
                "  0x{start:08X} - 0x{end:08X}  {:>10}  max {max:.3}",
                human_size((end - start) as u64)
            ));
        }
        if regions.len() > 200 {
            result.push_line(format!("  ... {} more", regions.len() - 200));
        }
        result.push_line("");
    }

    if req.is_checked(3) {
        for line in ascii_graph(&data, threshold) {
            result.push_line(line);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_high_entropy_region() {
        let mut data = vec![0u8; 1024];
        for (i, b) in data[512..768].iter_mut().enumerate() {
            *b = (i * 131 % 256) as u8;
        }
        let regions = high_regions(&data, 256, 7.0);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].0, 512);
        assert_eq!(regions[0].1, 768);
    }
}
