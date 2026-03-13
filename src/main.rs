use std::io;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use crate::dns_packet::{DnsPacketRef, DnsQuestion, DnsRecord, DnsRecordA, DnsRecordAAAA, DnsRecordCNAME, DnsRecordMX, DnsRecordNS, DnsRecordSOA, Flags, Opcode, PacketBuilder, Rcode};
use crate::message_handler::{handle_tcp, handle_udp};
use crate::resource::RecordResource;
// use tokio::sync::mpsc;

mod controller;
mod resource;
mod codec;
mod dns_packet;
mod message_handler;

#[tokio::main]
async fn main() -> io::Result<()> {
    let tcp_listener = TcpListener::bind("127.0.0.1:5300").await?;
    let udp_sock = UdpSocket::bind(("0.0.0.0", 5300)).await?;

    let _ = RecordResource::default();

    let store = Arc::new(record_store().await);
    tokio::select! {
        _ = handle_tcp(&tcp_listener, store.clone()) => {
            println!("do_stuff_async() completed first")
        }
        _ = handle_udp(&udp_sock, store.clone()) => {
            println!("do_stuff_async() completed first")
        }
    }
    Ok(())
}

async fn record_store() -> HashMap<u16, Vec<DnsRecord>> {
    let mut map = HashMap::new();
    let record1 = DnsRecordA {
        domain_name: "www.guokeyun.com".to_string(),
        record_class: 1,
        record_type: 0x0001,
        ttl: 600,
        length: 4,
        data: [124, 16, 31, 99]
    };
    map.entry(record1.record_type).or_insert(Vec::new()).push(record1.into());

    let record2 = DnsRecordA {
        domain_name: "www.guokeyun.com".to_string(),
        record_class: 1,
        record_type: 0x0001,
        ttl: 600,
        length: 4,
        data: [124, 16, 31, 100]
    };
    map.entry(record2.record_type).or_insert(Vec::new()).push(record2.into());

    let record3 = DnsRecordAAAA {
        domain_name: "www.guokeyun.com".to_string(),
        record_class: 1,
        record_type: 0x001c,
        ttl: 600,
        length: 16,
        data: [0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34]
    };
    map.entry(record3.record_type).or_insert(Vec::new()).push(record3.into());

    let record4 = DnsRecordCNAME {
        domain_name: "www.guokeyun.com".to_string(),
        record_class: 1,
        record_type: 0x0005,
        ttl: 600,
        length: 0,
        data: "test.guokeyun.com".to_string(),
    };
    map.entry(record4.record_type).or_insert(Vec::new()).push(record4.into());

    let record5 = DnsRecordMX {
        domain_name: "www.guokeyun.com".to_string(),
        record_class: 1,
        record_type: 0x000f,
        ttl: 600,
        length: 0,
        preference: 10,
        exchange: "mail.guokeyun.com".to_string(),
    };
    map.entry(record5.record_type).or_insert(Vec::new()).push(record5.into());

    let record6 = DnsRecordMX {
        domain_name: "www.guokeyun.com".to_string(),
        record_class: 1,
        record_type: 0x000f,
        ttl: 600,
        length: 0,
        preference: 20,
        exchange: "124.16.31.56".to_string(),
    };
    map.entry(record6.record_type).or_insert(Vec::new()).push(record6.into());

    let record7 = DnsRecordNS {
        domain_name: "www.guokeyun.com".to_string(),
        record_class: 1,
        record_type: 0x0002,
        ttl: 600,
        length: 0,
        data: "ns1.sfn.cn".to_string(),
    };
    map.entry(record7.record_type).or_insert(Vec::new()).push(record7.into());

    let record8 = DnsRecordSOA {
        domain_name: "www.guokeyun.com".to_string(),
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
    map.entry(record8.record_type).or_insert(Vec::new()).push(record8.into());

    map
}

async fn create_packet<'a>(id: u16, question: &'a DnsQuestion) -> PacketBuilder<DnsPacketRef<'a>> {
    let mut builder = PacketBuilder::<DnsPacketRef>::default();
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
    builder.add_question(question);
    builder
}