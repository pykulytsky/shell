use std::{
    process::ExitStatus,
    sync::{Arc, Mutex},
};
use tokio::{
    io,
    sync::mpsc::{error::SendError, UnboundedSender},
    task::JoinHandle,
};

#[derive(Debug)]
pub(crate) struct Job<R = Option<io::Result<ExitStatus>>> {
    pub(crate) handle: JoinHandle<R>,
    pub(crate) pid: Option<u32>,
}

impl<R> Job<R> {
    pub fn new(handle: JoinHandle<R>) -> Self {
        Self { handle, pid: None }
    }

    pub fn new_with_pid(handle: JoinHandle<R>, pid: u32) -> Self {
        Self {
            handle,
            pid: Some(pid),
        }
    }
}

pub(crate) type JobList = std::collections::HashMap<tokio::task::Id, Job>;

pub trait Context {
    fn set_pid(
        &self,
        job_id: tokio::task::Id,
        pid: Option<u32>,
    ) -> Result<(), SendError<(tokio::task::Id, Option<u32>)>>;

    fn remove(&self, job_id: tokio::task::Id) -> Result<(), SendError<tokio::task::Id>>;
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
    fn set_pid(
        &self,
        job_id: tokio::task::Id,
        pid: Option<u32>,
    ) -> Result<(), SendError<(tokio::task::Id, Option<u32>)>> {
        self.set_pid_tx.send((job_id, pid))
    }

    fn remove(&self, job_id: tokio::task::Id) -> Result<(), SendError<tokio::task::Id>> {
        self.bg_job_remove_tx.send(job_id)
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
    fn set_pid(
        &self,
        _job_id: tokio::task::Id,
        pid: Option<u32>,
    ) -> Result<(), SendError<(tokio::task::Id, Option<u32>)>> {
        let mut lock = self.pid.lock().unwrap();
        *lock = pid;
        Ok(())
    }

    fn remove(&self, _job_id: tokio::task::Id) -> Result<(), SendError<tokio::task::Id>> {
        self.pid.lock().unwrap().take();

        Ok(())
    }
}

impl Clone for FgContext {
    fn clone(&self) -> Self {
        Self {
            pid: self.pid.clone(),
        }
    }
}
