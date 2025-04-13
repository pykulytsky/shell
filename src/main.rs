use shell::Shell;

#[tokio::main]
async fn main() {
    let mut shell = Shell::new().await;
    let _ = shell.start().await;
}
