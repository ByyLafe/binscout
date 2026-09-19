use crate::analysis::read_target;
use crate::engine::runner::{absorb, run_command, tool_available};
use crate::engine::{Status, StepRequest, StepResult};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::time::Duration;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub fn imphash(data: &[u8]) -> Result<String, String> {
    match goblin::Object::parse(data) {
        Ok(goblin::Object::PE(pe)) => {
            if pe.imports.is_empty() {
                return Err("PE has no import table".into());
            }
            // Same recipe as pefile/Mandiant (lowercase dll without extension, ordN for ordinals,
            // import-table order) so the value can be compared with other tools.
            let parts: Vec<String> = pe
                .imports
                .iter()
                .map(|imp| {
                    let dll = imp.dll.to_lowercase();
                    let dll = dll
                        .strip_suffix(".dll")
                        .or_else(|| dll.strip_suffix(".ocx"))
                        .or_else(|| dll.strip_suffix(".sys"))
                        .unwrap_or(&dll);
                    let func = if imp.name.is_empty() {
                        format!("ord{}", imp.ordinal)
                    } else {
                        imp.name.to_lowercase()
                    };
                    format!("{dll}.{func}")
                })
                .collect();
            Ok(hex(&Md5::digest(parts.join(",").as_bytes())))
        }
        Ok(_) => Err("imphash is only defined for PE files".into()),
        Err(e) => Err(format!("not a parseable executable: {e}")),
    }
}

pub fn run(req: &StepRequest) -> StepResult {
    let mut result = StepResult::new(req.step);
    let data = match read_target(&req.target) {
        Ok(d) => d,
        Err(e) => return StepResult::failed(req.step, e),
    };

    let none = !req.any_checked();
    let sha256 = sha256_hex(&data);
    result.push_line(format!(
        "size    {} ({} bytes)",
        crate::analysis::human_size(data.len() as u64),
        data.len()
    ));
    if none || req.is_checked(0) {
        result.push_line(format!("sha256  {sha256}"));
    }
    if none || req.is_checked(1) {
        result.push_line(format!("md5     {}", hex(&Md5::digest(&data))));
    }
    if none || req.is_checked(2) {
        result.push_line(format!("sha1    {}", hex(&Sha1::digest(&data))));
    }
    if req.is_checked(3) {
        if tool_available("ssdeep") {
            let raw = run_command(
                "ssdeep",
                &["-b".to_string(), req.target.to_string_lossy().into_owned()],
            );

            if let Some(line) = raw.stdout.lines().nth(1) {
                let h = line.rsplit_once(',').map(|(h, _)| h).unwrap_or(line);
                result.push_line(format!("ssdeep  {}", h.trim_matches('"')));
                result.raw.push(raw);
            } else {
                absorb(&mut result, raw);
            }
        } else {
            result.push_line("ssdeep  not installed (apt install ssdeep)");
        }
    }
    if req.is_checked(4) {
        match imphash(&data) {
            Ok(h) => result.push_line(format!("imphash {h}")),
            Err(e) => result.push_line(format!("imphash n/a ({e})")),
        }
    }
    if req.is_checked(6) {
        result.push_line("");
        match malwarebazaar(&sha256) {
            Ok(lines) => {
                for l in lines {
                    result.push_line(l);
                }
            }
            Err(e) => {
                result.status = Status::Failed;
                result.push_line(format!("MalwareBazaar: {e}"));
            }
        }
    }
    if req.is_checked(5) {
        result.push_line("");
        match virustotal(&sha256) {
            Ok(lines) => {
                for l in lines {
                    result.push_line(l);
                }
            }
            Err(e) => {
                result.status = Status::Failed;
                result.push_line(format!("VirusTotal: {e}"));
            }
        }
    }
    result
}

fn virustotal(sha256: &str) -> Result<Vec<String>, String> {
    if crate::engine::runner::dry_run() {
        return Ok(vec![format!(
            "GET https://www.virustotal.com/api/v3/files/{sha256} (x-apikey)"
        )]);
    }
    let key = crate::config::get().vt_api_key().ok_or_else(|| {
        "set vt_api_key in config.toml or the VT_API_KEY environment variable".to_string()
    })?;

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(20)))
        .http_status_as_error(false)
        .build()
        .into();
    let url = format!("https://www.virustotal.com/api/v3/files/{sha256}");
    let mut resp = agent
        .get(&url)
        .header("x-apikey", key.trim())
        .call()
        .map_err(|e| format!("request failed: {e}"))?;
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp
        .body_mut()
        .read_json()
        .map_err(|e| format!("bad JSON from VirusTotal: {e}"))?;

    match status {
        200 => {}
        404 => {
            return Ok(vec![
                "VirusTotal: hash unknown (file never submitted)".to_string(),
            ]);
        }
        401 | 403 => return Err("invalid API key".into()),
        429 => return Err("quota exceeded, retry later".into()),
        s => {
            return Err(format!(
                "HTTP {s}: {}",
                body["error"]["message"].as_str().unwrap_or("")
            ));
        }
    }

    let attrs = &body["data"]["attributes"];
    let stats = &attrs["last_analysis_stats"];
    let n = |k: &str| stats[k].as_u64().unwrap_or(0);
    let malicious = n("malicious");
    let total = malicious + n("suspicious") + n("undetected") + n("harmless");
    let mut lines = vec![
        format!("VirusTotal: {malicious}/{total} engines flag this file as malicious"),
        format!(
            "  suspicious {}  undetected {}  harmless {}",
            n("suspicious"),
            n("undetected"),
            n("harmless")
        ),
    ];
    if let Some(label) = attrs["popular_threat_classification"]["suggested_threat_label"].as_str() {
        lines.push(format!("  threat label: {label}"));
    }
    if let Some(names) = attrs["names"].as_array() {
        let names: Vec<&str> = names.iter().filter_map(|v| v.as_str()).take(5).collect();
        if !names.is_empty() {
            lines.push(format!("  known names: {}", names.join(", ")));
        }
    }
    if let Some(ts) = attrs["last_analysis_date"].as_i64()
        && let Some(dt) = chrono::DateTime::from_timestamp(ts, 0)
    {
        lines.push(format!(
            "  last analysis: {}",
            dt.format("%Y-%m-%d %H:%M UTC")
        ));
    }
    lines.push(format!("  https://www.virustotal.com/gui/file/{sha256}"));
    Ok(lines)
}

pub fn malwarebazaar(sha256: &str) -> Result<Vec<String>, String> {
    if crate::engine::runner::dry_run() {
        return Ok(vec![format!(
            "POST https://mb-api.abuse.ch/api/v1/ query=get_info hash={sha256} (Auth-Key)"
        )]);
    }
    let key = crate::config::get().bazaar_api_key();
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(20)))
        .http_status_as_error(false)
        .build()
        .into();
    let mut request = agent.post("https://mb-api.abuse.ch/api/v1/");
    if let Some(k) = &key {
        request = request.header("Auth-Key", k.trim());
    }
    let mut resp = request
        .send_form([("query", "get_info"), ("hash", sha256)])
        .map_err(|e| format!("request failed: {e}"))?;
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp
        .body_mut()
        .read_json()
        .map_err(|e| format!("bad JSON from MalwareBazaar (HTTP {status}): {e}"))?;
    let qs = body["query_status"].as_str().unwrap_or("");
    // abuse.ch returns a bare {"error": "Unauthorized"} without query_status, so the
    // generic branch below would print an empty status.
    if status == 401 || status == 403 {
        return Err(format!(
            "HTTP {status} {}: an Auth-Key is required. Get a free one at https://auth.abuse.ch/ and set bazaar_api_key in config.toml or MALWAREBAZAAR_API_KEY",
            body["error"].as_str().unwrap_or("unauthorized")
        ));
    }
    match qs {
        "ok" => {}
        "hash_not_found" => {
            return Ok(vec![
                "MalwareBazaar: hash not found (not a known sample)".to_string(),
            ]);
        }
        "illegal_hash" => return Err("hash rejected".into()),
        "unknown_auth_key" | "missing_auth_key" | "auth_key_required" => {
            return Err(format!(
                "{qs}: set bazaar_api_key in config.toml or MALWAREBAZAAR_API_KEY (free key at https://auth.abuse.ch/)"
            ));
        }
        other => return Err(format!("HTTP {status}, query_status={other}")),
    }
    let Some(entry) = body["data"].as_array().and_then(|a| a.first()) else {
        return Ok(vec!["MalwareBazaar: empty answer".to_string()]);
    };
    let s = |k: &str| entry[k].as_str().unwrap_or("-").to_string();
    let mut lines = vec![
        format!("MalwareBazaar: KNOWN MALWARE sample ({})", s("file_type")),
        format!("  signature   {}", s("signature")),
        format!("  file name   {}", s("file_name")),
        format!("  first seen  {}  by {}", s("first_seen"), s("reporter")),
    ];
    if let Some(tags) = entry["tags"].as_array() {
        let t: Vec<&str> = tags.iter().filter_map(|v| v.as_str()).collect();
        if !t.is_empty() {
            lines.push(format!("  tags        {}", t.join(", ")));
        }
    }
    if let Some(dr) = entry["delivery_method"].as_str() {
        lines.push(format!("  delivery    {dr}"));
    }
    if let Some(v) = entry["vendor_intel"].as_object() {
        let vendors: Vec<&String> = v.keys().collect();
        lines.push(format!("  vendor intel from {} source(s)", vendors.len()));
    }
    lines.push(format!("  https://bazaar.abuse.ch/sample/{sha256}/"));
    Ok(lines)
}
