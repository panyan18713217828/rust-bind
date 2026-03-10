use std::{io, net::SocketAddr};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};
use crate::codec::{DnsDecoder, DnsEncoder};
use crate::dns_packet::{DnsPacketBuilder, DnsQuestion, DnsRecordA, DnsRecordAAAA, DnsRecordCNAME, DnsRecordMX, DnsRecordNS, DnsRecordSOA, Flags, Opcode, Rcode};
// use tokio::sync::mpsc;

mod controller;
mod resource;
mod codec;
mod dns_packet;

#[tokio::main]
async fn main() -> io::Result<()> {
    let tcp_listener = TcpListener::bind("127.0.0.1:5300").await?;
    let udp_sock = UdpSocket::bind(("0.0.0.0", 5300)).await?;

    tokio::select! {
         _ = handle_tcp(&tcp_listener) => {
            println!("do_stuff_async() completed first")
        }
        _ = handle_udp(&udp_sock) => {
            println!("do_stuff_async() completed first")
        }
    }
    Ok(())
}

//dig @127.0.0.1 -p 5300 www.guokeyun.com
async fn handle_tcp(tcp_listener: &TcpListener) -> io::Result<()> {
    loop {
        let (mut socket, addr) = tcp_listener.accept().await?;
        println!("TCP connection from: {}", addr);

        // 为每个 TCP 连接创建一个新任务
        tokio::spawn(async move {
            let mut buf = [0; 1024];

            loop {
                match socket.read(&mut buf).await {
                    Ok(0) => {
                        // 连接关闭
                        println!("TCP connection closed from: {}", addr);
                        break;
                    }
                    Ok(n) => {
                        println!("TCP received {} bytes from {}", n, addr);
                        break;
                    }
                    Err(e) => {
                        eprintln!("Failed to read TCP from {}: {}", addr, e);
                        break;
                    }
                }
            }
        });
    }
}

async fn handle_udp(udp_socket: &UdpSocket) -> Result<(), anyhow::Error> {
    loop {
        let decoder = DnsDecoder::new();
        let mut buf = [0; 4096];
        let (_, addr) = udp_socket.recv_from(&mut buf).await?;
        let packet = decoder.decode(&buf)?;
        let question = packet.questions.first().unwrap();
        let domain_name = question.domain_name.as_str();
        println!("{}", domain_name);

        let encoder = DnsEncoder::new();
        let data = encoder.encode(&create_packet(packet.header.id, domain_name, question.q_type).await);
        let d = data.as_slice();
        let _ = udp_socket.send_to(d, addr).await?;
    }
}

async fn create_packet(id: u16, domain_name: &str, q_type: u16) -> dns_packet::DnsPacket {
    let mut builder = DnsPacketBuilder::new();
    builder.id(id);
    let flags = Flags {
        qr: true,
        oc: Opcode::QUERY,
        aa: true,
        tc: false,
        rd: true,
        ra: true,
        z: 0,
        rc: Rcode::NOERROR,
    };
    builder.flag(flags);
    let question = DnsQuestion {
        domain_name: domain_name.to_string(),
        q_type,
        q_class: 0x0001,
    };
    builder.add_question(question);

    let record1 = DnsRecordA {
        domain_name: domain_name.to_string(),
        record_class: 1,
        record_type: 0x0001,
        ttl: 600,
        length: 4,
        data: [124, 16, 31, 99]
    };
    builder.add_answer(record1.into());
    let record2 = DnsRecordA {
        domain_name: domain_name.to_string(),
        record_class: 1,
        record_type: 0x0001,
        ttl: 600,
        length: 4,
        data: [124, 16, 31, 100]
    };
    builder.add_answer(dns_packet::DnsRecord::from(record2));
    let record3 = DnsRecordAAAA {
        domain_name: domain_name.to_string(),
        record_class: 1,
        record_type: 0x001c,
        ttl: 600,
        length: 16,
        data: [0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34]
    };
    builder.add_answer(record3.into());
    let record4 = DnsRecordCNAME {
        domain_name: domain_name.to_string(),
        record_class: 1,
        record_type: 0x0005,
        ttl: 600,
        length: 0,
        data: "test.guokeyun.com".to_string(),
    };
    builder.add_answer(record4.into());
    let record5 = DnsRecordMX {
        domain_name: domain_name.to_string(),
        record_class: 1,
        record_type: 0x000f,
        ttl: 600,
        length: 0,
        preference: 10,
        exchange: "mail.guokeyun.com".to_string(),
    };
    builder.add_answer(record5.into());
    let record6 = DnsRecordMX {
        domain_name: domain_name.to_string(),
        record_class: 1,
        record_type: 0x000f,
        ttl: 600,
        length: 0,
        preference: 20,
        exchange: "124.16.31.56".to_string(),
    };
    builder.add_answer(record6.into());
    let record7 = DnsRecordNS {
        domain_name: domain_name.to_string(),
        record_class: 1,
        record_type: 0x0002,
        ttl: 600,
        length: 0,
        data: "ns1.sfn.cn".to_string(),
    };
    builder.add_answer(record7.into());
    let record8 = DnsRecordSOA {
        domain_name: domain_name.to_string(),
        record_class: 1,
        record_type: 0x0006,
        ttl: 600,
        length: 0,
        mname: "ns1.sfn.cn".to_string(),
        rname: "admin@guokeyun.com".to_string(),
        serial: 10,
        refresh: 600,
        retry: 10,
        expire: 10,
        minimum: 600,
    };
    builder.add_answer(record8.into());
    builder.build()
}