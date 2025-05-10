use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use shell::readline::vim::{Motion, VimCommand};

#[tokio::main]
async fn main() {
    let mut stdin = tokio::io::stdin();

    loop {
        enable_raw_mode().unwrap();
        let Ok(Some(command)) = VimCommand::read(&mut stdin).await else {
            break;
        };

        disable_raw_mode().unwrap();
        dbg!(&command);
        if command.motion == Motion::TextObject('\u{4}') {
            break;
        }
    }
}
