use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::UdpSocket;
use crate::codec::{DnsDecoder, DnsEncoder};
use crate::dns_packet::{DnsPacketRef, DnsRecord, Rcode};
use crate::{create_packet, record_store};

//dig @127.0.0.1 -p 5300 www.guokeyun.com
pub async fn handle_udp(udp_socket: &UdpSocket, store: Arc<HashMap<u16, Vec<DnsRecord>>>) -> Result<(), anyhow::Error> {
    loop {
        let decoder = DnsDecoder::new();
        let mut buf = [0; 4096];
        let (size, addr) = udp_socket.recv_from(&mut buf).await?;
        let packet = decoder.decode(&buf)?;
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
        let _ = udp_socket.send_to(d, addr).await?;
    }
}