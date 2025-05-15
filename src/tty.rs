use libc::{sigaction, sighandler_t, SA_RESTART, SIGTSTP};
use nix::sys::termios::{tcgetattr, tcsetattr, LocalFlags, SetArg, SpecialCharacterIndices};
use std::{mem::zeroed, os::fd::AsFd};
use tokio::io;

#[allow(unused)]
pub(crate) unsafe fn override_sigtstp() {
    let mut sa: sigaction = zeroed();
    sa.sa_flags = SA_RESTART;
    sa.sa_sigaction = handle_sigtstp as usize as sighandler_t;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(SIGTSTP, &sa, std::ptr::null_mut());
}

pub extern "C" fn handle_sigtstp(_signum: i32) {}

pub(crate) fn disable_ctrl_z(fd: &tokio::io::Stdin) -> io::Result<()> {
    let mut termios = tcgetattr(fd).unwrap();
    termios.control_chars[SpecialCharacterIndices::VSUSP as usize] = 0;
    tcsetattr(fd, SetArg::TCSANOW, &termios).unwrap();
    Ok(())
}

pub(crate) fn enable_cbreak_mode() -> std::io::Result<()> {
    let fd = tokio::io::stdin().as_fd().try_clone_to_owned()?;
    let mut termios = tcgetattr(&fd)?;

    termios
        .local_flags
        .remove(LocalFlags::ICANON | LocalFlags::ECHO);

    termios.control_chars[nix::libc::VMIN] = 1;
    termios.control_chars[nix::libc::VTIME] = 0;

    tcsetattr(fd, SetArg::TCSANOW, &termios)?;
    Ok(())
}

pub(crate) fn disable_cbreak_mode() -> std::io::Result<()> {
    let fd = io::stdin().as_fd().try_clone_to_owned()?;
    let mut termios = tcgetattr(&fd)?;

    termios
        .local_flags
        .insert(LocalFlags::ICANON | LocalFlags::ECHO);

    termios.control_chars[nix::libc::VMIN] = 0;
    termios.control_chars[nix::libc::VTIME] = 1;

    tcsetattr(fd, SetArg::TCSAFLUSH, &termios)?;
    Ok(())
}
