//! A single authenticated elevated session for a complete ALT scan.

use crate::error::AppError;
use crate::service_helper;
use crate::strategy_scan::{self, ScanProgress, ScanRequest};
use serde::{Deserialize, Serialize};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0};
use windows_sys::Win32::Storage::FileSystem::{
    ReadFile, FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX, SYNCHRONIZE,
};
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, GetNamedPipeServerProcessId, PIPE_NOWAIT, PIPE_READMODE_MESSAGE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
};

const MAX_SCAN_FRAME: usize = 2 * 1024 * 1024;
const CONNECT_BUFFER: u32 = 64 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum RequestFrame {
    Scan { request: ScanRequest },
    Recover,
    Cancel,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum ResponseFrame {
    Progress {
        progress: ScanProgress,
    },
    Finished {
        result: Option<ScanProgress>,
        error: Option<AppError>,
    },
}

#[derive(Clone, Copy)]
enum Channel {
    Progress,
    Cancel,
}

fn pipe_name(id: &str, channel: Channel) -> String {
    let suffix = match channel {
        Channel::Progress => "Progress",
        Channel::Cancel => "Cancel",
    };
    format!(r"\\.\pipe\ZapretGui-Scan-{id}-{suffix}")
}

fn scan_error(message: &'static str) -> AppError {
    AppError::new(
        "strategy_scan_transport",
        message,
        "Повторите действие после проверки состояния стратегии.",
    )
}

fn send<T: Serialize>(pipe: HANDLE, frame: &T) -> Result<(), AppError> {
    let bytes =
        serde_json::to_vec(frame).map_err(|_| scan_error("Ошибка формата сканирования."))?;
    if bytes.len() > MAX_SCAN_FRAME {
        return Err(scan_error(
            "Результаты сканирования превысили допустимый размер.",
        ));
    }
    service_helper::write_message(pipe, &bytes)
}

fn receive<T: for<'de> Deserialize<'de>>(pipe: HANDLE) -> Result<T, AppError> {
    let mut bytes = vec![0; MAX_SCAN_FRAME];
    let mut read = 0;
    if unsafe {
        ReadFile(
            pipe,
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            &mut read,
            null_mut(),
        )
    } == 0
        || read == 0
        || read as usize > bytes.len()
    {
        return Err(scan_error(
            "Канал сканирования закрылся до получения ответа.",
        ));
    }
    bytes.truncate(read as usize);
    serde_json::from_slice(&bytes)
        .map_err(|_| scan_error("Помощник вернул неверный ответ сканирования."))
}

pub(crate) fn invoke_scan(
    request: ScanRequest,
    cancelled: Arc<AtomicBool>,
    on_progress: impl FnMut(ScanProgress),
) -> Result<ScanProgress, AppError> {
    invoke(RequestFrame::Scan { request }, cancelled, on_progress)?
        .ok_or_else(|| scan_error("Помощник не вернул итог сканирования."))
}

pub(crate) fn invoke_recovery(on_progress: impl FnMut(ScanProgress)) -> Result<(), AppError> {
    invoke(
        RequestFrame::Recover,
        Arc::new(AtomicBool::new(false)),
        on_progress,
    )
    .map(|_| ())
}

fn invoke(
    request: RequestFrame,
    cancelled: Arc<AtomicBool>,
    mut on_progress: impl FnMut(ScanProgress),
) -> Result<Option<ScanProgress>, AppError> {
    let id = service_helper::new_pipe_id()?;
    // A blocking read and a write on the same synchronous pipe handle can
    // serialize behind each other. Keep cancellation on its own connection:
    // the progress pipe is request -> results, while the other is cancel only.
    let progress_pipe = create_pipe(&id, Channel::Progress)?;
    let cancel_pipe = create_pipe(&id, Channel::Cancel)?;
    let app = service_helper::verify_installed_app()?;
    let helper = service_helper::launch_scan_helper(&app, &id)?;
    service_helper::connect_verified_helper(progress_pipe.0, helper.0)?;
    service_helper::connect_verified_helper(cancel_pipe.0, helper.0)?;
    send(progress_pipe.0, &request)?;

    let done = Arc::new(AtomicBool::new(false));
    let cancel_thread = {
        let done = Arc::clone(&done);
        let cancelled = Arc::clone(&cancelled);
        let pipe_handle = cancel_pipe.0 as usize;
        thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                if cancelled.load(Ordering::SeqCst) {
                    let _ = send(pipe_handle as HANDLE, &RequestFrame::Cancel);
                    return;
                }
                thread::sleep(Duration::from_millis(50));
            }
        })
    };
    let result = loop {
        let frame: ResponseFrame = match receive(progress_pipe.0) {
            Ok(frame) => frame,
            Err(error) => break Err(error),
        };
        match frame {
            ResponseFrame::Progress { progress } => on_progress(progress),
            ResponseFrame::Finished { result, error } => {
                break match (result, error) {
                    (Some(result), None) => Ok(Some(result)),
                    (None, None) => Ok(None),
                    (None, Some(error)) => Err(error),
                    _ => Err(scan_error("Помощник вернул неоднозначный результат.")),
                };
            }
        }
    };
    done.store(true, Ordering::SeqCst);
    let _ = cancel_thread.join();
    if unsafe { WaitForSingleObject(helper.0, 10_000) } != WAIT_OBJECT_0 {
        return Err(scan_error("Помощник сканирования не завершился."));
    }
    result
}

fn create_pipe(id: &str, channel: Channel) -> Result<service_helper::Handle, AppError> {
    let name = service_helper::wide(&pipe_name(id, channel));
    let raw = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            CONNECT_BUFFER,
            CONNECT_BUFFER,
            0,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(scan_error(
            "Не удалось открыть защищённый канал сканирования.",
        ));
    }
    Ok(service_helper::Handle(raw))
}

pub(crate) fn run_helper() -> i32 {
    match helper_session() {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn helper_session() -> Result<(), AppError> {
    let app = service_helper::verify_installed_app()?;
    if !crate::manual_helper::elevated()? {
        return Err(scan_error("Помощник не получил права администратора."));
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 || args[0] != "--scan-ipc" || !service_helper::valid_pipe_id(&args[1]) {
        return Err(scan_error("Неверные параметры помощника сканирования."));
    }
    let progress_pipe = service_helper::connect_pipe(&pipe_name(&args[1], Channel::Progress))
        .ok_or_else(|| scan_error("Не удалось подключиться к каналу сканирования."))?;
    let cancel_pipe = service_helper::connect_pipe(&pipe_name(&args[1], Channel::Cancel))
        .ok_or_else(|| scan_error("Не удалось подключиться к каналу отмены сканирования."))?;
    let mut parent_pid = 0;
    if unsafe { GetNamedPipeServerProcessId(progress_pipe.0, &mut parent_pid) } == 0
        || parent_pid == 0
    {
        return Err(scan_error(
            "Не удалось проверить основной процесс приложения.",
        ));
    }
    let mut cancel_parent_pid = 0;
    if unsafe { GetNamedPipeServerProcessId(cancel_pipe.0, &mut cancel_parent_pid) } == 0
        || cancel_parent_pid != parent_pid
    {
        return Err(scan_error(
            "Канал отмены не принадлежит основному процессу приложения.",
        ));
    }
    let parent = service_helper::Handle(unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
            0,
            parent_pid,
        )
    });
    if parent.0.is_null() || parent.0 == INVALID_HANDLE_VALUE {
        return Err(scan_error(
            "Не удалось открыть основной процесс приложения.",
        ));
    }
    crate::manual_helper::verify_parent(parent.0, &app)?;
    let request: RequestFrame = receive(progress_pipe.0)?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let cancel_listener = Arc::clone(&cancelled);
    let pipe_handle = cancel_pipe.0 as usize;
    thread::spawn(move || {
        let pipe = pipe_handle as HANDLE;
        loop {
            match receive::<RequestFrame>(pipe) {
                Ok(RequestFrame::Cancel) | Err(_) => {
                    cancel_listener.store(true, Ordering::SeqCst);
                    return;
                }
                _ => {}
            }
        }
    });
    let outcome = match request {
        RequestFrame::Scan { request } => strategy_scan::run_scan(
            request,
            |progress| {
                if send(
                    progress_pipe.0,
                    &ResponseFrame::Progress {
                        progress: progress.clone(),
                    },
                )
                .is_err()
                {
                    cancelled.store(true, Ordering::SeqCst);
                }
            },
            || cancelled.load(Ordering::SeqCst),
        )
        .map(Some),
        RequestFrame::Recover => strategy_scan::recover_pending(|progress| {
            if send(
                progress_pipe.0,
                &ResponseFrame::Progress {
                    progress: progress.clone(),
                },
            )
            .is_err()
            {
                cancelled.store(true, Ordering::SeqCst);
            }
        })
        .map(|_| None),
        RequestFrame::Cancel => Err(scan_error("Пустой запрос сканирования.")),
    };
    let response = match outcome {
        Ok(result) => ResponseFrame::Finished {
            result,
            error: None,
        },
        Err(error) => ResponseFrame::Finished {
            result: None,
            error: Some(error),
        },
    };
    let _ = send(progress_pipe.0, &response);
    Ok(())
}
