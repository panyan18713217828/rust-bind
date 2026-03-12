use std::collections::HashMap;
use std::sync::Arc;
use anyhow::{anyhow, Error};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use crate::codec::{DnsDecoder, DnsEncoder};
use crate::{create_packet, record_store};
use crate::dns_packet::{DnsPacketRef, DnsRecord, Rcode};

//dig @127.0.0.1 -p 5300 www.guokeyun.com +tcp
pub async fn handle_tcp(tcp_listener: &TcpListener, store: Arc<HashMap<u16, Vec<DnsRecord>>>) -> Result<(), Error> {
    loop {
        let (stream, addr) = tcp_listener.accept().await?;
        let store = store.clone();
        tokio::spawn(async move {
            match handle(stream, store).await {
                Ok(_) => {}
                Err(_) => {}
            }
        });
    }
}

async fn handle(mut stream: TcpStream, store: Arc<HashMap<u16, Vec<DnsRecord>>>) -> Result<(), Error> {
    loop {
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(()); // 客户端关闭连接，正常退出
            }
            Err(e) => return Err(anyhow!(e)),
        }
        let len = u16::from_be_bytes(len_buf);
        let mut request = vec![0u8; len as usize];
        stream.read_exact(&mut request).await?;

        let decoder = DnsDecoder::new();
        let packet = decoder.decode(request.as_slice())?;
        let question = packet.questions.first().unwrap();
        let domain_name = question.domain_name.as_str();
        println!("{}", domain_name);

        let encoder = DnsEncoder::<DnsPacketRef>::new();
        let mut builder = create_packet(packet.header.id, &question).await;
        let data = store.get(&question.q_type);
        let packet = match data {
            Some(data) => {
                for answer in data {
                    builder.add_answer(answer);
                }
                builder.build()
            },
            None => {
                if let Some(soa_records) = store.get(&0x0006) {
                    for soa in soa_records {
                        builder.add_authority(soa);
                    }
                }
                let mut p = builder.build();
                p.header.flags.rc = Rcode::NXDOMAIN;
                p
            }
        };

        let data = encoder.encode(packet);
        let d = data.as_slice();
        stream.write_u16(data.len() as u16).await?;
        stream.write_all(d).await?;
        stream.flush().await?;
    }
}