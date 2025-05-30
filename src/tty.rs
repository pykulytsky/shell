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

pub fn disable_ctrl_z(fd: &tokio::io::Stdin) -> io::Result<()> {
    let mut termios = tcgetattr(fd).unwrap();
    termios.control_chars[SpecialCharacterIndices::VSUSP as usize] = 0;
    tcsetattr(fd, SetArg::TCSANOW, &termios).unwrap();
    Ok(())
}

pub fn enable_cbreak_mode() -> std::io::Result<()> {
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

pub fn disable_cbreak_mode() -> std::io::Result<()> {
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

pub fn drain_pty(fd: impl AsFd) {
    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    use nix::unistd::read;

    let mut buf = [0u8; 1024];

    let old_flags = fcntl(&fd, FcntlArg::F_GETFL).unwrap();
    fcntl(
        &fd,
        FcntlArg::F_SETFL(OFlag::from_bits_truncate(old_flags) | OFlag::O_NONBLOCK),
    )
    .unwrap();

    while read(&fd, &mut buf).unwrap_or(0) > 0 {}

    fcntl(fd, FcntlArg::F_SETFL(OFlag::from_bits_truncate(old_flags))).unwrap();
}
