#[allow(unused_imports)]
use std::io::{self, Write};

use codecrafters_shell::command::Command;

fn main() {
    // Uncomment this block to pass the first stage
    let stdin = io::stdin();

    // Wait for user input
    let mut input = String::new();
    loop {
        print!("$ ");
        io::stdout().flush().unwrap();
        stdin.read_line(&mut input).unwrap();
        match Command::read(&input[..input.len() - 1]) {
            Ok(command) => command.run(),
            Err(err) => eprintln!("{err}"),
        }
        input.clear();
    }
}
