use std::io;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use crate::dns_packet::{DnsPacketRef, DnsQuestion, DnsRecordA, DnsRecordAAAA, DnsRecordCNAME, DnsRecordMX, DnsRecordNS, DnsRecordSOA, Flags, Opcode, PacketBuilder, Rcode};
use crate::message_handler::{handle_tcp, handle_udp};
use crate::resource::{RadixTree};
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

async fn record_store() -> RadixTree {
    let mut radix_tree = RadixTree::default();

    let record0 = DnsRecordA {
        domain_name: "*.example.com".to_string(),
        record_class: 1,
        record_type: 0x0001,
        ttl: 600,
        length: 4,
        data: [127, 0, 0, 1],
    };
    radix_tree.add_record("*.example.com".to_string(), record0.into());

    let record1 = DnsRecordA {
        domain_name: "www.example.com".to_string(),
        record_class: 1,
        record_type: 0x0001,
        ttl: 600,
        length: 4,
        data: [124, 16, 31, 99]
    };
    radix_tree.add_record("www.example.com".to_string(), record1.into());

    let record2 = DnsRecordA {
        domain_name: "www.example.com".to_string(),
        record_class: 1,
        record_type: 0x0001,
        ttl: 600,
        length: 4,
        data: [124, 16, 31, 100]
    };
    radix_tree.add_record("www.example.com".to_string(), record2.into());

    let record3 = DnsRecordAAAA {
        domain_name: "aaaa.example.com".to_string(),
        record_class: 1,
        record_type: 0x001c,
        ttl: 600,
        length: 16,
        data: [0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34]
    };
    radix_tree.add_record("aaaa.example.com".to_string(), record3.into());

    let record4 = DnsRecordCNAME {
        domain_name: "www.example.com".to_string(),
        record_class: 1,
        record_type: 0x0005,
        ttl: 600,
        length: 0,
        data: "test.example.com".to_string(),
    };
    radix_tree.add_record("www.example.com".to_string(), record4.into());

    let record5 = DnsRecordMX {
        domain_name: "www.example.com".to_string(),
        record_class: 1,
        record_type: 0x000f,
        ttl: 600,
        length: 0,
        preference: 10,
        exchange: "mail.example.com".to_string(),
    };
    radix_tree.add_record("www.example.com".to_string(), record5.into());

    let record6 = DnsRecordMX {
        domain_name: "www.example.com".to_string(),
        record_class: 1,
        record_type: 0x000f,
        ttl: 600,
        length: 0,
        preference: 20,
        exchange: "124.16.31.56".to_string(),
    };
    radix_tree.add_record("www.example.com".to_string(), record6.into());

    let record7 = DnsRecordNS {
        domain_name: "ns1.example.com".to_string(),
        record_class: 1,
        record_type: 0x0002,
        ttl: 600,
        length: 0,
        data: "ns1.sfn.cn".to_string(),
    };
    radix_tree.add_record("ns1.example.com".to_string(), record7.into());

    let record8 = DnsRecordSOA {
        domain_name: "www.example.com".to_string(),
        record_class: 1,
        record_type: 0x0006,
        ttl: 600,
        length: 0,
        mname: "ns1.sfn.cn".to_string(),
        rname: "admin@example.com".to_string(),
        serial: 10,
        refresh: 600,
        retry: 10,
        expire: 10,
        minimum: 600,
    };
    radix_tree.add_record("www.example.com".to_string(), record8.into());

    radix_tree
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