use anyhow::Error;
use async_channel::{Receiver, RecvError};
use tokio::sync::mpsc::UnboundedSender;
use std::net::SocketAddr;
use std::sync::Arc;
use std::str;
use tokio::sync::oneshot::channel;
use crate::rsnmp::{
    handler,
    handler::SecurityParameters,
};
use crate::settings;

#[derive(Debug)]
struct ParseResult {
    response: Option<Vec<u8>>,
    error: Option<Error>,
}

fn community_check(
    config: Arc<settings::Settings>,
    community: &[u8],
) -> Result<(), Error> {
    if config.snmptrapd.auth.enable {
        let community = str::from_utf8(community)
            .map_err(|_| Error::msg("community is not valid string"))?;
        if !config.snmptrapd.auth.is_community_allowed(community) {
            return Err(Error::msg(format!("community not allowed: {}", community)));
        }
    }
    Ok(())
}

fn parse_snmp_packet(
    data: Vec<u8>,
    config: Arc<settings::Settings>,
) -> ParseResult {
    let mut result = ParseResult{
        response: None,
        error: None,
    };
    let m = handler::decode_message(&data);
    match m {
        Ok(handler::Message::V1(m)) => {
            result.error = community_check(config.clone(), &m.message.community).err();
        },
        Ok(handler::Message::V2C(m)) => {
            result.response = m.response;
            result.error = community_check(config.clone(), &m.message.community).err();
        },
        Ok(handler::Message::V3(mut m)) => {
            let SecurityParameters::USM(usm) = &m.security_parameters;
            match str::from_utf8(&usm.user_name) {
                Ok(username) => {
                    if let Some(user) = config.snmptrapd.auth.get_user(username) {
                        let e = m.process(
                            user.minimum_security_level(),
                            user.auth_type,
                            user.auth_passphrase.as_ref(),
                            user.privacy_protocol,
                            user.privacy_passphrase.as_ref(),
                            user.skip_timeliness_checks,
                        ).err();
                        if let Some(e) = e {
                            result.error = Some(Error::from(e));
                        }
                        result.response = m.response;
                    } else {
                        result.error = Some(Error::msg(format!("username not allowed: {}", username)));
                    }
                },
                Err(_) => {
                    result.error = Some(Error::msg("username is not valid string"));
                }
            }
        },
        Err(e) => {
            result.error = Some(Error::from(e));
        }
    }
    result
}

pub async fn parse_worker(
    r: Receiver<(Vec<u8>, SocketAddr, usize)>,
    informs: Vec<UnboundedSender<(Vec<u8>, SocketAddr)>>,
    config: Arc<settings::Settings>,
) -> Result<(), Error> {
    loop {
        match r.recv().await {
            Ok(data) => {
                let (send, recv) = channel();
                let config = config.clone();
                let (payload, addr, socket_idx) = data;
                rayon::spawn(move || {
                    let r = parse_snmp_packet(
                        payload,
                        config,
                    );
                    if let Some(e) = r.error {
                        log::debug!(target = "parser"; "failed processing message: {}", e.to_string());
                    }
                    send.send(r.response).unwrap();
                });
                if let Some(payload) = recv.await? {
                    informs[socket_idx].send((payload, addr))?;
                }
            }
            Err(RecvError) => {
                log::debug!(target = "parser"; "worker shutdown");
                return Ok(());
            }
        }
    }
}