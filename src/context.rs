use std::{
    process::ExitStatus,
    sync::{Arc, Mutex},
};
use tokio::{
    io,
    sync::mpsc::{error::SendError, UnboundedSender},
    task::JoinHandle,
};

#[derive(Debug, PartialEq)]
pub(crate) enum JobStatus {
    Running,
    Paused,
}

#[derive(Debug)]
pub(crate) struct Job<R = Option<io::Result<ExitStatus>>> {
    pub(crate) handle: JoinHandle<R>,
    pub(crate) pid: Option<u32>,
    pub(crate) status: JobStatus,
}

impl<R> Job<R> {
    pub fn new(handle: JoinHandle<R>) -> Self {
        Self {
            handle,
            pid: None,
            status: JobStatus::Running,
        }
    }

    pub fn new_with_pid(handle: JoinHandle<R>, pid: u32) -> Self {
        Self {
            handle,
            pid: Some(pid),
            status: JobStatus::Running,
        }
    }
}

pub(crate) type JobRegistry = std::collections::HashMap<tokio::task::Id, Job>;

pub trait Context {
    type Result;

    fn set_pid(&self, job_id: tokio::task::Id, pid: Option<u32>) -> Self::Result;

    fn remove(&self, job_id: tokio::task::Id) -> Self::Result;
}

#[derive(Debug)]
pub(crate) struct BgContext {
    bg_job_remove_tx: UnboundedSender<tokio::task::Id>,
    set_pid_tx: UnboundedSender<(tokio::task::Id, Option<u32>)>,
}

impl BgContext {
    pub fn new(
        remove_tx: UnboundedSender<tokio::task::Id>,
        set_pid_tx: UnboundedSender<(tokio::task::Id, Option<u32>)>,
    ) -> Self {
        Self {
            bg_job_remove_tx: remove_tx,
            set_pid_tx,
        }
    }
}

impl Context for BgContext {
    type Result = Result<(), SendError<(tokio::task::Id, Option<u32>)>>;
    fn set_pid(&self, job_id: tokio::task::Id, pid: Option<u32>) -> Self::Result {
        self.set_pid_tx.send((job_id, pid))
    }

    fn remove(&self, job_id: tokio::task::Id) -> Self::Result {
        self.bg_job_remove_tx
            .send(job_id)
            .map_err(|err| SendError((err.0, None)))
    }
}

impl Clone for BgContext {
    fn clone(&self) -> Self {
        Self {
            bg_job_remove_tx: self.bg_job_remove_tx.clone(),
            set_pid_tx: self.set_pid_tx.clone(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct FgContext {
    pid: Arc<Mutex<Option<u32>>>,
}

impl FgContext {
    pub fn new(pid: &Arc<Mutex<Option<u32>>>) -> Self {
        Self { pid: pid.clone() }
    }
}

impl Context for FgContext {
    type Result = ();
    fn set_pid(&self, _job_id: tokio::task::Id, pid: Option<u32>) -> Self::Result {
        let mut lock = self.pid.lock().unwrap();
        *lock = pid;
    }

    fn remove(&self, _job_id: tokio::task::Id) -> Self::Result {
        self.pid.lock().unwrap().take();
    }
}

impl Clone for FgContext {
    fn clone(&self) -> Self {
        Self {
            pid: self.pid.clone(),
        }
    }
}
