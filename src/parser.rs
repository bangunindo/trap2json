use anyhow::Error;
use async_channel::{Receiver, RecvError};
use tokio::sync::mpsc::UnboundedSender;
use std::net::SocketAddr;
use rasn::ber::{decode, encode};
use rasn::Codec;
use rasn_snmp::{v1, v2, v2c, v3};
use crate::rsnmp::{cipher, auth};

fn parse_snmp_packet(
    data: Vec<u8>,
    addr: SocketAddr,
    socket_idx: usize,
    send: tokio::sync::oneshot::Sender<Option<(Vec<u8>, SocketAddr, usize)>>,
) -> () {
    if let Ok(message) = decode::<v2c::Message<v2::Pdus>>(&data) {
        println!("{:?}", message);
        match message.data {
            v2::Pdus::InformRequest(ref req) => {
                let mut resp = message.clone();
                let mut req = req.0.clone();
                req.error_index = 0;
                req.error_status = v2::Pdu::ERROR_STATUS_NO_ERROR;
                resp.data = v2::Pdus::Response(v2::Response(req));
                let data = encode(&resp).unwrap();
                send.send(Some((data, addr, socket_idx))).unwrap();
                return;
            }
            v2::Pdus::Trap(trap) => {}
            _ => {}
        }
    } else if let Ok(mut message) = decode::<v3::Message>(&data) {
        match message.decode_security_parameters::<v3::USMSecurityParameters>(Codec::Ber) {
            Ok(res) => {
                println!("{:0x}", res.authoritative_engine_id);
                println!("{:?}", res);
                if let v3::ScopedPduData::EncryptedPdu(ref payload) = message.scoped_data {
                    let cipher_algo = cipher::CipherType::DES;
                    let hash_algo = auth::AuthType::MD5;
                    let mut payload = payload.clone().to_vec();
                    let pdu_data = cipher_algo.decrypt(
                        hash_algo,
                        &mut payload,
                        b"sssssssss",
                        res.authoritative_engine_boots.to_u32_digits().1[0],
                        res.authoritative_engine_time.to_u32_digits().1[0],
                        &res.authoritative_engine_id,
                        &res.privacy_parameters,
                    );
                    match pdu_data {
                        Err(e) => {
                            println!("{}", e);
                        }
                        Ok(_) => {
                            if let Ok(pdu) = decode::<v3::ScopedPdu>(&payload) {
                                message.scoped_data = v3::ScopedPduData::CleartextPdu(pdu);
                            }
                        }
                    }
                }
            }
            _ => {}
        };
        println!("{:?}", message);
    } else if let Ok(message) = decode::<v1::Message<v1::Pdus>>(&data) {
        println!("{:?}", message);
    } else {
        log::debug!(target = "parse_worker"; "cannot decode snmp packet");
    }

    send.send(None).unwrap();
}

pub async fn parse_worker(
    r: Receiver<(Vec<u8>, SocketAddr, usize)>,
    informs: Vec<UnboundedSender<(Vec<u8>, SocketAddr)>>,
) -> Result<(), Error> {
    loop {
        match r.recv().await {
            Ok(data) => {
                let (send, recv) = tokio::sync::oneshot::channel();
                rayon::spawn(move || {
                    parse_snmp_packet(
                        data.0,
                        data.1,
                        data.2,
                        send,
                    );
                });
                if let Some((data, addr, socket_idx)) = recv.await? {
                    informs[socket_idx].send((data, addr))?;
                }
            }
            Err(RecvError) => {
                log::debug!(target = "parse_worker"; "worker shutdown");
                return Ok(());
            }
        }
    }
}