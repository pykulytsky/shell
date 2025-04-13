use std::env::current_dir;

use tokio::io::AsyncWriteExt;
use tokio::io::{self, AsyncWrite};

pub trait Prompt {
    fn draw<S: AsyncWrite + Unpin>(
        &self,
        sink: S,
    ) -> impl std::future::Future<Output = io::Result<()>>;
}

#[derive(Debug)]
pub struct DefaultPrompt;

impl Prompt for DefaultPrompt {
    async fn draw<S: AsyncWrite + Unpin>(&self, mut sink: S) -> io::Result<()> {
        sink.write_u8(b'$').await?;
        sink.write_u8(b' ').await?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct DirPrompt;

impl Prompt for DirPrompt {
    async fn draw<S: AsyncWrite + Unpin>(&self, mut sink: S) -> io::Result<()> {
        let current_dir = current_dir()?;
        let dir_name = current_dir
            .file_name()
            .unwrap_or_else(|| current_dir.as_os_str())
            .to_string_lossy();

        sink.write_all(dir_name.as_bytes()).await?;
        sink.write_u8(b' ').await?;

        Ok(())
    }
}
