use std::process::exit;
use std::{fs::DirEntry, os::unix::fs::PermissionsExt};
pub mod command;
use std::process::Command as SysCommand;

use command::Command;
use std::{
    fs::read_dir,
    io::{self, Write},
};

#[derive(Debug, Default)]
pub struct Shell {
    pub path: String,
    pub path_executables: Vec<DirEntry>,
}

impl Shell {
    pub fn new() -> Self {
        let path = std::env::var("PATH").unwrap_or("".to_string());
        let path_executables: Vec<DirEntry> = path
            .split(":")
            .flat_map(read_dir)
            .flatten()
            .flatten()
            .filter(|f| {
                let Ok(metadata) = f.metadata() else {
                    return false;
                };
                (metadata.is_file() || metadata.is_symlink())
                    && metadata.permissions().mode() & 0o111 != 0
            })
            .collect();
        Self {
            path,
            path_executables,
        }
    }

    pub fn start(&mut self) {
        let stdin = io::stdin();

        let mut input = String::new();
        loop {
            print!("$ ");
            io::stdout().flush().unwrap();
            stdin.read_line(&mut input).unwrap();
            match Command::read(&input[..input.len() - 1], self) {
                Ok(command) => self.run(command),
                Err(err) => eprintln!("{err}"),
            }
            input.clear();
        }
    }

    fn get_path_executable(&self, name: &str) -> Option<&DirEntry> {
        self.path_executables
            .iter()
            .find(|e| e.path().components().last().unwrap().as_os_str() == name)
    }

    pub fn run(&self, command: Command) {
        match command {
            Command::Exit { status_code } => exit(status_code),
            Command::Echo { msg } => println!("{msg}"),
            Command::Type { command } => match command.as_ref() {
                c if matches!(c, "exit" | "echo" | "type" | "pwd") => {
                    println!("{c} is a shell builtin")
                }
                c if self.get_path_executable(c).is_some() => {
                    let entry = self.get_path_executable(c).unwrap();
                    println!("{c} is {}", entry.path().as_path().to_string_lossy());
                }
                c => eprintln!("{c}: not found"),
            },
            Command::Pwd => {
                let pwd = std::env::current_dir().unwrap();
                println!("{}", pwd.display());
            }
            Command::Program { name, input } => {
                let mut stdout = io::stdout();
                let mut stderr = io::stderr();
                let canonicalized_name = self.canonicalize_path(name.to_str().unwrap()).unwrap();
                let output = SysCommand::new(canonicalized_name)
                    .args(input.split(" "))
                    .output()
                    .unwrap();
                stdout.write_all(&output.stdout).unwrap();
                stderr.write_all(&output.stderr).unwrap();
            }
            Command::Cd { path } => {
                let home = std::env::var("HOME").unwrap();
                let mut cd_path = path.clone();

                if path == "~" {
                    cd_path = home;
                }

                let _ = std::env::set_current_dir(&cd_path).map_err(|_e| {
                    eprintln!("cd: {path}: No such file or directory");
                });
            }
        }
    }

    pub fn canonicalize_path<P: AsRef<str> + ?Sized>(&self, path: &P) -> Option<String> {
        for p in self.path.split(":") {
            if path.as_ref().contains(p) {
                return Some(path.as_ref().replace(p, "").replace("/", ""));
            }
        }
        Some(path.as_ref().to_string())
    }
}
