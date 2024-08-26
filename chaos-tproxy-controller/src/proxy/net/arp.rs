use std::fmt;
use std::net::Ipv4Addr;

use libarp::arp::{ArpMessage, Operation};
use libarp::interfaces::{Interface, MacAddr};
use pnet::packet::ethernet::EtherTypes;

struct DebugMacAddr(MacAddr);

impl fmt::Debug for DebugMacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0 .0, self.0 .1, self.0 .2, self.0 .3, self.0 .4, self.0 .5
        )
    }
}

struct DebugArpMessage(ArpMessage);

impl fmt::Debug for DebugArpMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ArpMessage {{ ... }}") // Customize this to show relevant fields
    }
}

pub fn gratuitous_arp(interface: Interface, ip_addr: Ipv4Addr, mac_addr: MacAddr) {
    tracing::info!("Preparing to send gratuitous ARP");
    tracing::info!("Interface: {:?}", interface);
    tracing::info!("IP Address: {:?}", ip_addr);
    tracing::info!("MAC Address: {:?}", DebugMacAddr(mac_addr));

    let arp_request = ArpMessage::new(
        EtherTypes::Arp,
        mac_addr,
        ip_addr,
        MacAddr(0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
        ip_addr,
        Operation::ArpRequest,
    );

    tracing::info!(
        "Gratuitous ARP request created: {:?}",
        DebugArpMessage(arp_request)
    );

    match arp_request.send(&interface) {
        Ok(_) => tracing::info!("Gratuitous ARP sent successfully"),
        Err(e) => tracing::error!("Gratuitous ARP send failed: {}", e),
    }
}
