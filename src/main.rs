use crate::dns_packet::{
    DnsPacket, DnsRecord, DnsRecordData, QueryClass, QueryType, Serialization,
};
use std::{io, net::SocketAddr};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};
use crate::dns_packet_new::dns_packet::RawDnsPacket;
use crate::dns_packet_new::dns_packet_info::DnsPacketInfo;
use crate::dns_packet_new::name_pointer_lookup::{DataList, NamePointerLookup, NamePointerEntry};
// use tokio::sync::mpsc;

mod controller;
mod dns_packet;
mod dns_packet_new;
mod persistence;
mod resource;

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
                        let mut packet = DnsPacket::from_bytes(&buf, &mut 0).unwrap();
                        println!("{}", packet.questions.pop().unwrap().name);
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

async fn handle_udp(udp_socket: &UdpSocket) -> io::Result<()> {
    loop {
        let (mut packet, addr) = read_dns_packet(udp_socket).await?;
        let record1 = DnsRecord::StandardDnsRecord {
            name: "www.guokeyun.com".to_string(),
            q_type: QueryType::A,
            q_class: QueryClass::IN,
            ttl: 600,
            length: 4,
            data: DnsRecordData::A(Box::from([124, 16, 31, 99])),
        };
        let record2 = DnsRecord::StandardDnsRecord {
            name: "www.guokeyun.com.".to_string(),
            q_type: QueryType::A,
            q_class: QueryClass::IN,
            ttl: 600,
            length: 4,
            data: DnsRecordData::A(Box::from([124, 16, 31, 100])),
        };
        let record3 = DnsRecord::StandardDnsRecord {
            name: "www.guokeyun.com.".to_string(),
            q_type: QueryType::AAAA,
            q_class: QueryClass::IN,
            ttl: 600,
            length: 16,
            data: DnsRecordData::AAAA(Box::from([
                0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70,
                0x73, 0x34,
            ])),
        };
        let mut record4_data: Vec<String> = Vec::new();
        record4_data.push("aaa".to_string());
        record4_data.push("你好".to_string());
        let mut data_length = 0;
        for data in &record4_data {
            data_length += data.len();
        }

        let record4 = DnsRecord::StandardDnsRecord {
            name: "www.guokeyun.com.".to_string(),
            q_type: QueryType::TXT,
            q_class: QueryClass::IN,
            ttl: 600,
            length: 5 + "你好".as_bytes().len() as u16,
            data: DnsRecordData::TXT(record4_data),
        };
        packet.answers.push(record1);
        packet.answers.push(record2);
        packet.answers.push(record3);
        // packet.answers.push(record4);

        // let authority = DnsRecord::StandardDnsRecord {
        //     name: "localhost.".to_string(),
        //     q_type: QueryType::A,
        //     q_class: QueryClass::IN,
        //     ttl: 600,
        //     length: 4,
        //     data: DnsRecordData::A([127, 0, 0, 1]),
        // };
        let mut buf = [0; 4096];
        let mut offset = 0;
        // packet.header.flags.rc = 0x3;
        packet.header.ar_count = 0;
        packet.header.an_count = packet.answers.len() as u16;
        // packet.header.ns_count = 1;
        packet.to_bytes(&mut buf, &mut offset);
        let _ = udp_socket.send_to(&buf[..offset], addr).await?;
    }
}

async fn read_dns_packet(udp_socket: &UdpSocket) -> io::Result<(DnsPacket, SocketAddr)> {
    let mut buf = [0; 4096];
    let (_, addr) = udp_socket.recv_from(&mut buf).await?;
    let packet = DnsPacket::from_bytes(&buf, &mut 0).unwrap();
    let mut lookup = NamePointerLookup::default();
    if let Ok(packet2) = RawDnsPacket::try_from((&buf[..], &mut lookup)) {
        if let Ok(info) = DnsPacketInfo::try_from(packet2) {
            println!("{}", info.question.first().unwrap().names);
        } else {
            todo!()
        }
    } else {
        todo!()
    }

    let mut b = [0; 4096];
    packet.header.to_bytes(&mut b, &mut 0);
    Ok((packet, addr))
}