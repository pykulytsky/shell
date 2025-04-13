use codecrafters_shell::{
    prompt::{DefaultPrompt, DirPrompt},
    readline::{signal::Signal, Readline},
};

#[tokio::main]
async fn main() {
    // let mut readline = Readline::new().await;
    let mut readline = Readline::new_with_prompt(DirPrompt).await;

    loop {
        let mut input = String::new();
        let signal = readline.read(&mut input).await.unwrap();
        if signal == Signal::CtrlD {
            return;
        }
        println!("{:?}\r", input);
    }
}
