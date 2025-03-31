use codecrafters_shell::Shell;

#[tokio::main]
async fn main() {
    let mut shell = Shell::new();
    shell.start();
}
