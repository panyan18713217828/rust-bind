use std::sync::Arc;
use tokio::net::UdpSocket;
use crate::codec::{DnsDecoder, DnsEncoder};
use crate::dns_packet::{DnsPacketRef, Rcode};
use crate::{create_packet};
use crate::resource::RadixTree;

//dig @127.0.0.1 -p 5300 www.example.com
pub async fn handle_udp(udp_socket: &UdpSocket, store: Arc<RadixTree>) -> Result<(), anyhow::Error> {
    loop {
        let decoder = DnsDecoder::new();
        let mut buf = [0; 4096];
        let (_, addr) = udp_socket.recv_from(&mut buf).await?;
        let packet = decoder.decode(&buf)?;
        let question = packet.questions.first().unwrap();
        let domain_name = question.domain_name.as_str();
        println!("{}", domain_name);

        let encoder = DnsEncoder::<DnsPacketRef>::new();
        let mut builder = create_packet(packet.header.id, &question).await;
        let data = store.select_record(&question);
        let packet = if data.is_empty() {
            // for soa in soa_records {
            //     builder.add_authority(soa);
            // }
            let mut p = builder.build();
            p.header.flags.rc = Rcode::NXDOMAIN;
            p
        } else {
            for answer in data {
                builder.add_answer(answer);
            }
            builder.build()
        };

        let data = encoder.encode(packet);
        let d = data.as_slice();
        let _ = udp_socket.send_to(d, addr).await?;
    }
}