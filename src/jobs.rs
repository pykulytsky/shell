use libc::{sigaction, sighandler_t, SA_RESTART, SIGTSTP};
use std::mem::zeroed;
use std::process::ExitStatus;

use tokio::{
    io,
    sync::mpsc::{error::SendError, UnboundedSender},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub(crate) struct Job<R = Option<io::Result<ExitStatus>>> {
    pub(crate) handle: JoinHandle<R>,
    pub(crate) pid: Option<u32>,
}

impl<R> Job<R> {
    pub fn new(handle: JoinHandle<R>) -> Self {
        Self { handle, pid: None }
    }
}

pub(crate) type JobList = std::collections::HashMap<tokio::task::Id, Job>;

#[derive(Debug)]
pub(crate) struct JobContext {
    bg_job_remove_tx: UnboundedSender<tokio::task::Id>,
    bg_job_set_pid_tx: UnboundedSender<(tokio::task::Id, Option<u32>)>,
    pub(crate) global_cancelation_token: CancellationToken,
}

impl JobContext {
    pub fn new(
        remove_tx: UnboundedSender<tokio::task::Id>,
        set_pid_tx: UnboundedSender<(tokio::task::Id, Option<u32>)>,
        token: CancellationToken,
    ) -> Self {
        Self {
            bg_job_remove_tx: remove_tx,
            bg_job_set_pid_tx: set_pid_tx,
            global_cancelation_token: token,
        }
    }

    pub fn set_pid(
        &self,
        job_id: tokio::task::Id,
        pid: Option<u32>,
    ) -> Result<(), SendError<(tokio::task::Id, Option<u32>)>> {
        self.bg_job_set_pid_tx.send((job_id, pid))
    }

    pub fn remove(&self, job_id: tokio::task::Id) -> Result<(), SendError<tokio::task::Id>> {
        self.bg_job_remove_tx.send(job_id)
    }
}

impl Clone for JobContext {
    fn clone(&self) -> Self {
        Self {
            bg_job_remove_tx: self.bg_job_remove_tx.clone(),
            bg_job_set_pid_tx: self.bg_job_set_pid_tx.clone(),
            global_cancelation_token: self.global_cancelation_token.clone(),
        }
    }
}

pub unsafe fn override_sigtstp() {
    let mut sa: sigaction = zeroed();
    sa.sa_flags = SA_RESTART;
    sa.sa_sigaction = handle_sigtstp as usize as sighandler_t;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(SIGTSTP, &sa, std::ptr::null_mut());
}

pub extern "C" fn handle_sigtstp(_signum: i32) {}
