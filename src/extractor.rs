use std::fs;
use std::path::Path;
use std::process::Command;

use regex::Regex;
use walkdir::WalkDir;

const SENSITIVE : &[&str] = &[
    "passwd",
    "shadow",
    ".key",
    ".crt",
    ".pem",
    "wpa_supplicant",
    "hostapd",
    "dropbear"
];

pub fn extract(firmware: &str, out_dir: &str) {
    let _ = fs::create_dir_all(out_dir);
    let status = Command::new("binwalk")
        .arg("-e")
        .arg(firmware)
        .status()
        .expect("Failed to read file");
    if !status.success(){
        eprintln!("[!] binwalk return {:?}",status.code());
    }
}
