use std::collections::HashSet;
use pnet::datalink::{self, Channel, DataLinkReceiver, NetworkInterface};
use pnet::packet::MutablePacket;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use std::sync::mpsc::Sender;

use crate::scanner::ScanResult;

pub fn build_full_packet(
    packet_buffer: &mut [u8],
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    source_port: u16,
    target_port: u16,
) {
    // 1. Build IPv4 Header (20 bytes)
    let mut ip_packet = MutableIpv4Packet::new(&mut packet_buffer[..20]).unwrap();
    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_total_length(40); // 20 (IP) + 20 (TCP)
    ip_packet.set_ttl(64);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_packet.set_source(source_ip);
    ip_packet.set_destination(target_ip);

    // Calculate IP Checksum
    let checksum = pnet::packet::ipv4::checksum(&ip_packet.to_immutable());
    ip_packet.set_checksum(checksum);

    // 2. Build TCP Header (Starts from byte 20)
    let mut tcp_packet = MutableTcpPacket::new(&mut packet_buffer[20..40]).unwrap();
    tcp_packet.set_source(source_port);
    tcp_packet.set_destination(target_port);
    tcp_packet.set_sequence(rand::random::<u32>());
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(64240);
    tcp_packet.set_data_offset(5);

    // TCP Checksum requires Pseudo-Header (source/dest IPs)
    let tcp_checksum =
        pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &source_ip, &target_ip);
    tcp_packet.set_checksum(tcp_checksum);
}

pub fn get_active_interface() -> (NetworkInterface, Ipv4Addr) {
    let interfaces = datalink::interfaces();

    // نبحث عن أول كرت شبكة شغال وعنده عنوان IP (مو Loopback)
    let interface = interfaces
        .into_iter()
        .find(|iface: &NetworkInterface| {
            iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty()
        })
        .expect(
            "❌ No working network card was found! Make sure you are connected to the internet.",
        );

    let ip = interface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| match ip.ip() {
            IpAddr::V4(v4) => v4,
            _ => unreachable!(),
        })
        .expect("❌ The Card Does not Contain an Address IPv4.");

    (interface, ip)
}

pub fn run_stealth_scan(
    target_ip: Ipv4Addr,
    ports: Vec<u16>,
    services_map: Arc<HashMap<u16, (String, String)>>
) -> (Vec<ScanResult>, Duration) {
    let (interface, source_ip) = get_active_interface();
    let mut results = Vec::new();
    let scan_time = Instant::now();

    let (mut tx, rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => panic!("FailedToOpenChannel"),
    };

    // إنشاء القناة
    let (tx_results, rx_results) = mpsc::channel();

    start_listener(rx, target_ip, Arc::clone(&services_map), tx_results);

    // println!("ScanningTarget: {} | SourceIp: {}", target_ip, source_ip);

    let gateway_mac = MacAddr::from_str("58:d9:d5:ee:50:80").unwrap();

    for port in ports {
        let mut frame_buffer = [0u8; 54];
        let mut eth_packet = MutableEthernetPacket::new(&mut frame_buffer).unwrap();

        eth_packet.set_source(interface.mac.expect("NoMacFound"));
        eth_packet.set_destination(gateway_mac);
        eth_packet.set_ethertype(EtherTypes::Ipv4);

        build_full_packet(eth_packet.payload_mut(), source_ip, target_ip, 44444, port);

        if let Some(Err(e)) = tx.send_to(eth_packet.packet(), None) {
            eprintln!("SendError: {}", e);
        }

        thread::sleep(Duration::from_millis(20));
    }

    while let Ok(res) = rx_results.try_recv() {
        results.push(res);
    }

    
    thread::sleep(Duration::from_secs(3));
    let time_taken = scan_time.elapsed();
    (results, time_taken)
}

fn start_listener(
    mut rx: Box<dyn DataLinkReceiver>,
    target_ip: Ipv4Addr,
    services_map: Arc<HashMap<u16, (String, String)>>,
    tx_results: Sender<ScanResult>, // قناة لإرسال النتائج
) {
    let mut found_ports = HashSet::new(); // ما نحتاج Mutex هنا لأن الـ Thread واحد

    thread::spawn(move || {
        loop {
            if let Ok(frame) = rx.next() {
                let eth_packet = EthernetPacket::new(frame).unwrap();
                if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
                    if ip_packet.get_source() == target_ip {
                        if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                            let flags = tcp_packet.get_flags();
                            let port = tcp_packet.get_source();

                            if (flags & TcpFlags::SYN != 0) && (flags & TcpFlags::ACK != 0) {
                                if found_ports.insert(port) {
                                    let service_name = services_map.get(&port)
                                        .map(|(name, _)| name.clone())
                                        .unwrap_or_else(|| "unknown".to_string());

                                    let result = ScanResult {
                                        port,
                                        is_open: true,
                                        service: service_name,
                                        banner: None, // الـ Stealth scan ما يرجع بنر عادةً
                                    };
                                    let _ = tx_results.send(result);
                                }
                            }
                        }
                    }
                }
            }
        }
    });
}
