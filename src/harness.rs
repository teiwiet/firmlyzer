use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;

#[derive(Debug, Clone)]
pub enum RunResult {
    Ok,
    Crash { code: i32 },
    Timeout,
}

pub struct Harness {
    pub binary: String,
    pub timeout_ms: u64,
}

impl Harness {
    pub fn new(binary: &str, timeout_ms: u64) -> Self {
        Self {
            binary: binary.to_string(),
            timeout_ms,
        }
    }

    pub fn run(&self, input: &[u8]) -> RunResult {
        let mut child = match Command::new(&self.binary).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to spawn : {}", e);
                return RunResult::Crash { code: -1 };
            }
        };

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(input);
        }

        let timeout = Duration::from_millis(self.timeout_ms);
        match child.wait_timeout(timeout).unwrap() {
            None => {
                child.kill().unwrap();
                child.wait().unwrap();
                RunResult::Timeout
            }
            Some(status)=> {
                if status.success() {
                    RunResult::Ok
                } else {
                    let code = status.code().unwrap_or(-1);
                    RunResult::Crash {code}
                }
            }
        }
    }
}
