extern crate clap;
extern crate rand;
extern crate pnet;
extern crate btree;

use clap::*;
use std::vec::Vec;
use btree::PBTree;
use std::math::round;
use std::net::Ipv4Addr;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{Packet, MutablePacket};
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ip::{IpNextHeaderProtocols};
use pnet::packet::ipv4::{MutableIpv4Packet, ipv4_checksum};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use rand::distributions::Standard;

// Checks the difference between the list open ports and output from new scan
// Args:
//	opened - the list of opened ports
//	compare - the new list of open ports
// Returns:
//	A result containing the list of new ports or errors
fn check_new_opened(opened: Vec<(String, u16)>, compare: Vec<(String, u16)>) -> Result<Vec<(String, u16)>> {
	let mut indices = Vec::new();
	let mut next = Vec::new();
	compare.clone_into(next);

	let mut i = 0;
	for pair in opened {
		let mut j = 0;
		for comp in compare {
			if pair.0 == comp.0 && pair.1 == comp.1 {
				indices.append(j);
			}
			j += 1;
		}
		i += 1;
	}

	for index in indices {
		next.remove(index as usize);
	}

	if next.len() > 0 {
		Ok(next.to_owned())
	} else {
		Err(Error::new(""))
	}
}

// Check for opened ports
// Returns
//	A result containing a of vector of tuples
fn check_opened() -> Result<Vec<(String, u16)>> {
	unimplemented!();
}

// Generates a random sequence of ports
// ensuring that they are unique
// Args:
//	length -
//	storage -
// Returns:
//	A vector of tuples of shape [protocol, port]
fn gen_sequence(length: u8, storage: &mut PBTree<String, Vec<(String, u16)>>) -> Vec<(String, u16)> {
	let mut res = Vec::<(String, u16)>::new();

	// Loop through length and create
	for i in 1..length {
		//
		let proto: bool = rand::random::<bool>();
		let port: u16 = (rand::random::<f32>() * 65535.0).ceil() as u16;
		res.push((if proto { String::from("TCP") } else { String::from("UDP") }, port))
	}

	let parsed = res.iter().fold("" as String, |mut b, a| {
		b += fmt!("{:?},{:?};", a.0, a.1);
	});

	// Check if seq exists
	match storage.search(&parsed) {
		Ok(r) => match r {
			Some(v) => gen_sequence(length, storage),
			None => {
				match storage.insert(&parsed, &res) {
					Ok() => res,
					Err(error) => panic!(error.to_string())
				}
			}
		},
		Err(error) => panic!(error.to_string())
 	}
}

// Generates a SYN packets from port sequence
// Args:
//	ips -
//	seq -
// Returns:
//	A vector of vectors of packets
fn seq_to_packets(ips: (Ipv4Addr, Ipv4Addr), seq: Vec<(String,  u16)>) -> Vec<Vec<Packet>> {
	let res = vec!();

	const IPV4_HEADER_LEN: usize = 20;
	const TCP_HEADER_LEN: usize = 32;

	seq.iter().fold(Vec::new(), |mut b, a| {
		let mut packet = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN];

		{
			let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
			ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
			ip_header.set_source(ips.0);
			ip_header.set_destination(ips.1);
		}

		{
			let mut tcp_header = MutableTcpPacket::new(&mut packet[IPV4_HEADER_LEN..]).unwrap();
			tcp_header.set_source(49511);
			tcp_header.set_destination(a.1);
			tcp_header.set_sequence(0x9037d2b8);
			tcp_header.set_acknowledgement(0x944bb276);
			tcp_header.set_flags(TcpFlags::SYN);
			tcp_header.set_window(4015);
			tcp_header.set_data_offset(0);

			let ts = TcpOption::timestamp(743951781, 44056978);
			tcp_header.set_options(&vec![TcpOption::nop(), TcpOption::nop(), ts]);

			let checksum = ipv4_checksum(&tcp_header.to_immutable(), &ipv4_source, &ipv4_destination);
			tcp_header.set_checksum(checksum);
		}

		b.append(packet);
	})
}

// Main function
fn main() {
	// From args get:
	// sequence length
	// timeout duration
	// interface
	// ip address
	let app_matches = App::new("Knock Knock")
		.about("Port knocking client written in Rust")
		.author("Daniel Wanner <daniel.wanner@pm.me>")
		.version("0.1.3")
		.arg(
			Arg::with_name("sequence")
				.short("seq")
				.long("sequence")
				.help("Sequence Length"),
		)
		.arg(
			Arg::with_name("interval")
				.short("i")
				.long("interval")
				.help("Sets the interval between knocks")
				.takes_value(true)
				.default_value("1000"),
		)
		.arg(
			Arg::with_name("interface")
				.short("i")
				.long("interface")
				.required(true)
				.help("Sets the interval between knocks"),
		)
		.arg(
			Arg::with_name("ip")
				.index(1)
				.required(true)
				.help("The ip address to knock at"),
		)
		.arg(
			Arg::with_name("path")
				.index(2)
				.required(true)
				.help("The path to store the process database at."),
		)
		.get_matches();

	// Values
	let interface = app_matches.value_of("interface").unwrap();
	let path = app_matches.value_of("path").unwrap();
	let ip = app_matches.value_of("ip").unwrap();
	let length = app_matches.value_of("sequence").unwrap();

	let interface_names_match = |iface: &NetworkInterface| iface.name == interface.to_string();
    let mut storage = PBTree::<String, Vec<(String, u16)>>::new(path).unwrap();

	let link = datalink::interfaces().into_iter()
		.filter(interface_names_match)
		.next()
		.unwrap();

	// Create a new channel, dealing with layer 2 packets
	let (mut tx, mut rx) = match datalink::channel(&link, Default::default()) {
		Ok(Ethernet(tx, rx)) => (tx, rx),
		Ok(_) => panic!("Unhandled channel type"),
		Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
	};

	// TODO: Scan open ports
	let open = check_opened().unwrap();

	// The main loop
	loop {
		let seq = gen_sequence(u8::new(length), &mut storage);
		let packets = seq_to_packets((link.ips[0].ip() as Ipv4Addr, Ipv4Addr::from(ip.to_string())),seq);

		for packet_seq in packets {
			for packet in packet_seq {
				match tx.send_to(packet.packet(), None) {
					Ok() => continue,
					Err() => break
				}
				// TODO: Sleep thread for interval
			}
			// TODO: Scan for any open ports
		}
	}
}
