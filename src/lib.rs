extern crate crypto;
use crypto::digest::Digest;
use crypto::sha1::Sha1;

extern crate base64;
use base64::{engine::general_purpose, Engine as _};


use std::{net::TcpStream,fmt::Error,io::prelude::*,borrow::Borrow,};
pub struct ReadType {
    pub done: bool,
    pub message: String,
}

pub fn hash_ws_sec_key(sec_websocket_key: String) -> String{
    let mut hasher = Sha1::new();
    let trimmed_sec_websocket_key = sec_websocket_key.trim().to_string();
    let sec_websocket_key_magic = trimmed_sec_websocket_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    hasher.input_str(&sec_websocket_key_magic);
    let mut out = [0; 20];
    hasher.result(&mut out);
    let sec_websocket_key_magic_sha1_base64 = general_purpose::STANDARD.encode(out);
    sec_websocket_key_magic_sha1_base64
}


pub fn read_ws(stream: &mut TcpStream, fin_rsv_opcode: &mut u8) -> Result<ReadType, Error> {
    let mut buf: [u8; 2] = [0; 2];
    let read_sucess = stream.read_exact(&mut buf);
    let message = String::from("value");
    let mut payload_len: usize = 1;
    let mut mask_payload_len: u8 = 0;
    match read_sucess {
        Ok(_) => {
            println!("Got message!");
            *fin_rsv_opcode = buf[0];

            mask_payload_len = buf[1];
            if mask_payload_len - 128 > 125 {
                if mask_payload_len - 128 > 126 {
                    let mut len: [u8; 4] = [0; 4];
                    let _res = stream.read_exact(&mut len);
                    payload_len = ((len[0] as usize) << 24)
                        + ((len[1] as usize) << 16)
                        + ((len[2] as usize) << 8)
                        + (len[3] as usize);
                } else {
                    let mut len: [u8; 2] = [0; 2];
                    let _res = stream.read_exact(&mut len);
                    payload_len = ((len[0] as usize) << 8) + (len[1] as usize);
                }
            } else {
                payload_len = (mask_payload_len - 128) as usize;
            }
            println!("{}", mask_payload_len - 128);
            let mut encoded_message: Vec<u8> = vec![0; payload_len];
            let mut decoded_message: Vec<u8> = vec![];
            let mut mask: [u8; 4] = [0, 0, 0, 0];
            if mask_payload_len < 128 {
                println!("Mask bit not set...");
            } else {
                let _ = stream.read_exact(&mut mask);

                let _ = stream.read_exact(&mut encoded_message);

                //println!("{}",encoded_message[0]);
                for i in 0..encoded_message.len() {
                    decoded_message.push(encoded_message[i] ^ mask[i % 4]);
                }
                println!("{}", String::from_utf8_lossy(&decoded_message));
                println!("");
            }

            if *fin_rsv_opcode >= 128 {
                return Ok(ReadType {
                    done: true,
                    message: String::from_utf8_lossy(&decoded_message).to_string(),
                });
            } else {
                let res = read_ws(stream, fin_rsv_opcode);
                match res {
                    Ok(ok) => {
                        return Ok(ReadType {
                            done: true,
                            message: message + ok.message.borrow(),
                        })
                    }
                    Err(_) => {
                        println!("Crap");
                        Err(Error)
                    }
                }
            }
        }
        Err(_) => Err(Error),
    }
}
pub fn write_ws(stream: &mut TcpStream, message: String) -> Result<usize, std::io::Error> {
    let mut buf: Vec<u8> = vec![];
    buf.push(129);
    if message.len() > 125 {
        if message.len() > 65535 {
            buf.push(127);
            let u32_doc_len = (message.len()) as u32;
            buf.push((u32_doc_len >> 24) as u8);
            buf.push(((u32_doc_len << 8) >> 24) as u8);
            buf.push(((u32_doc_len << 16) >> 24) as u8);
            buf.push(((u32_doc_len << 24) >> 24) as u8);
        } else {
            buf.push(126);
            let u16_doc_len = (message.len()) as u16;
            buf.push((u16_doc_len >> 8) as u8);
            buf.push(((u16_doc_len << 8) >> 8) as u8);
        }
    } else {
        buf.push((message.len()) as u8)
    }
    for i in message.as_str().bytes() {
        buf.push(i);
    }
    return stream.write(&buf);
}
pub fn send_ws_stream(stream: &mut TcpStream, message: String, message_type: &str) -> Result<usize, std::io::Error> {
    return write_ws(stream, format!("{}|{}",message_type,message));
}
#[macro_export]
pub macro_rules! handle_websocket {
    ($stream:expr,$message:expr,$begins_with:expr,$anonymous_func:tt) => {
        if $message.starts_with($begins_with) {
            write_ws($stream,$anonymous_func());
        }
    };
}