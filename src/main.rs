use anyhow::Error;
use tokio::{
    net::UdpSocket,
    spawn,
    signal,
    io,
    sync::mpsc,
};
use structured_logger::{async_json::new_writer, Builder};
use simple_logger::SimpleLogger;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

mod parser;
mod settings;
mod rsnmp;


#[tokio::main]
async fn main() -> Result<(), Error> {
    let config = Arc::new(settings::Settings::new()?);
    match config.logger.format {
        settings::LogFormat::Console => {
            SimpleLogger::new()
                .with_level(log::LevelFilter::from_str(&config.logger.level.to_string())?)
                .init()
                .unwrap();
        },
        settings::LogFormat::Json => {
            Builder::with_level(&config.logger.level.to_string())
                .with_target_writer("*", new_writer(io::stderr()))
                .init();
        },
    }

    let mut socket_handlers = vec![];
    let mut informs = vec![];
    let (s, r) = async_channel::unbounded();
    for (idx, addr) in config.snmptrapd.listening.iter().enumerate() {
        let socket = UdpSocket::bind(addr).await?;
        let mut buf = vec![0u8; 4096];
        let s = s.clone();
        let (inform_s, mut inform_r) = mpsc::unbounded_channel::<(Vec<u8>, SocketAddr)>();
        let handle = spawn(async move {
            log::info!(target: "listener", listener_idx = idx+1; "Listening on: {}", socket.local_addr().unwrap());
            'main_loop:
            loop {
                tokio::select! {
                    res = socket.recv_from(&mut buf) => {
                        let (size, addr) = res.unwrap();
                        let data = bytes::Bytes::from(buf[..size].to_vec());
                        s.send((data, addr, idx)).await.unwrap();
                    }
                    res = inform_r.recv() => {
                        let (data, addr) = res.ok_or(Error::msg("closed inform channel")).unwrap();
                        socket.send_to(&data, addr).await.unwrap();
                    }
                    _ = signal::ctrl_c() => {
                        log::debug!(target: "listener", listener_idx = idx+1; "received termination signal, shutting down");
                        break 'main_loop;
                    }
                }
            }
            Ok(()) as Result<(), Error>
        });
        socket_handlers.push(handle);
        informs.push(inform_s);
    }

    let mut worker_handlers = vec![];
    for _ in 0..config.parse_workers {
        let r = r.clone();
        let informs = informs.clone();
        let conf_clone = config.clone();
        let handle = spawn(async move {
            parser::parse_worker(r, informs, conf_clone).await.unwrap();
            Ok(()) as Result<(), Error>
        });
        worker_handlers.push(handle);
    }

    for handle in socket_handlers {
        let _ = handle.await?;
    }
    log::debug!(target: "main", "shutting down worker");
    drop(s);
    for handle in worker_handlers {
        let _ = handle.await?;
    }
    let _ = io::stderr().flush().await?;
    log::info!(target: "main", "application shutdown");
    Ok(())
}
