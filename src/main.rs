use std::fs;
use std::env;
use std::process;
use std::error::Error;

use logwatch_rs::parser::{FailedLogin,parse_line};
fn main() {
    let args: Vec<String> = env::args().collect();
    
    let file_path = parse_config(&args).unwrap_or_else(|err| {
        println!("Problem parsing args:{err}");
        process::exit(1);
    });
    if let Err(e) = run(file_path) {
        println!("Application error: {e}");
        process::exit(1);
    }
    
    
    
}
fn parse_config(args: &[String]) -> Result<&str, &'static str> {
    if args.len() < 2 {
        return Err("not enough arguments");
    }
    Ok(&args[1])
}
fn run(path_to_file: &str) -> Result<(), Box<dyn Error>> {
    let contents = fs::read_to_string(path_to_file)?;
    println!("Inside run");
    let events: Vec<FailedLogin> = contents.lines().filter_map(parse_line).collect();
        for event in &events {
            println!("{} failed login: user={} ip={}", event.timestamp, event.user, event.ip);

        }
    Ok(())
}
