use crate::harness::{RunResult,Harness};
use crate::mutator::Mutator;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

pub struct Fuzzer{
    harness: Harness,
    mutator: Mutator,
    crash_dir : PathBuf,
    seeds : Vec<Vec<u8>>
}

impl Fuzzer {
    pub fn new(harness: Harness, crash_dir : &str,seeds : Vec<Vec<u8>>) -> Self{
        fs::create_dir_all(crash_dir).unwrap();
        Fuzzer{
            harness,
            mutator : Mutator::new(),
            crash_dir : PathBuf::from(crash_dir),
            seeds
        }
    }

    pub fn run(&mut self,max_iters : u64){
        let start = Instant::now();
        let mut crashes = 0u64;
        let mut timeout = 0u64;

        let mut corpus = self.seeds.clone();

        for i in 0..max_iters{
            let seed = corpus[i as usize % corpus.len()].clone();

            let input = self.mutator.mutate(&seed);
            match self.harness.run(&input){
                RunResult::Ok => {},
                RunResult::Crash {code} =>{
                    let is_real_crash = matches!(code,139|134|-1);
                    if is_real_crash {
                        crashes+=1;
                        let path = self.crash_dir.join(format!("crash_{i}_code{code}"));
                        fs::write(&path,&input).unwrap();
                        println!("[CRASH] iter={i} code={code} saved to {:?}",path);
                        corpus.push(input);
                    }
                }
                RunResult::Timeout => {
                    timeout+=1
                }
            }
            if i % 1000 == 0{
                let elapsed = start.elapsed().as_secs();
                let speed = if elapsed >0{i/elapsed} else {0};
                println!("[*] iter={i} crashes={crashes} timeouts={timeout} speed={speed}/s corpus={}",corpus.len());
            }
        }
        println!("\n[DONE] {} iters,{} crashes, {} timeouts",max_iters,crashes,timeout);
    }
}
