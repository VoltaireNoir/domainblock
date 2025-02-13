use std::{
    mem,
    net::{IpAddr, Ipv4Addr},
    ptr::write_bytes,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use clap::Parser;
use ndisapi::*;
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    NetworkManagement::Ndis::OID_802_3_CURRENT_ADDRESS,
    Networking::WinSock::{IN_ADDR, IN_ADDR_0, IN_ADDR_0_0, IPPROTO_TCP},
    System::Threading::{CreateEventW, ResetEvent, SetEvent, WaitForSingleObject},
};

#[derive(clap::Parser, Clone, Debug)]
enum Args {
    /// Block one or more domains on the specified network interface
    Block {
        /// Network interface index (use `interfaces` command to find the index)
        #[clap(short, long)]
        interface: usize,
        /// One of more space separated domains to block
        #[clap(short, long, num_args = 1..10)]
        domains: Vec<String>,
    },
    /// List all network interfaces
    Interfaces,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let driver =
        Ndisapi::new("NDISRD").expect("WinpkFilter driver is not installed or failed to load!");

    println!(
        "Detected Windows Packet Filter version {}",
        driver.get_version()?
    );

    let adapters = driver.get_tcpip_bound_adapters_info()?;

    let Args::Block { interface, domains } = args else {
        return list(&adapters, &driver);
    };

    println!("Using interface {}s", adapters[interface].get_name());
    block(&domains, &driver, adapters[interface].get_handle())?;

    Ok(())
}

fn resolve(domains: &[String]) -> anyhow::Result<Vec<Ipv4Addr>> {
    let resolver = trust_dns_resolver::Resolver::default()?;
    let mut ips = vec![];
    for h in domains {
        match resolver.lookup_ip(h) {
            Ok(resp) => {
                for ip in resp.iter() {
                    if let IpAddr::V4(add) = ip {
                        println!("Host: {h}, IP: {add}");
                        ips.push(add);
                    } else {
                        eprintln!("Error: encountered IPv6 address (unsupported)");
                    }
                }
            }
            Err(err) => eprintln!("Error while looking up IP: {err}"),
        }
    }
    if ips.is_empty() {
        anyhow::bail!("No IP addresses found for the provided hosts");
    }
    Ok(ips)
}

fn list(adapters: &[NetworkAdapterInfo], driver: &Ndisapi) -> anyhow::Result<()> {
    for (index, adapter) in adapters.iter().enumerate() {
        let network_interface_name = Ndisapi::get_friendly_adapter_name(adapter.get_name())
            .expect("Unknown network interface");
        println!(
            "{}. {}\n\t{}",
            index,
            network_interface_name,
            adapter.get_name(),
        );
        println!("\t Medium: {}", adapter.get_medium());
        println!(
            "\t MAC: {}",
            MacAddress::from_slice(adapter.get_hw_address()).unwrap_or_default()
        );
        println!("\t MTU: {}", adapter.get_mtu());
        println!(
            "\t FilterFlags: {:?}",
            driver.get_adapter_mode(adapter.get_handle()).unwrap()
        );

        // Query hardware packet filter for the adapter using built wrapper for ndis_get_request
        match driver.get_hw_packet_filter(adapter.get_handle()) {
            Err(err) => println!(
                "Getting OID_GEN_CURRENT_PACKET_FILTER Error: {}",
                err.message()
            ),
            Ok(current_packet_filter) => {
                println!("\t OID_GEN_CURRENT_PACKET_FILTER: 0x{current_packet_filter:08X}")
            }
        }

        // Query MAC address of the network adapter using ndis_get_request directly
        let mut current_address_request = PacketOidData::new(
            adapter.get_handle(),
            OID_802_3_CURRENT_ADDRESS,
            MacAddress::default(),
        );
        if let Err(err) = driver.ndis_get_request::<_>(&mut current_address_request) {
            println!("Getting OID_802_3_CURRENT_ADDRESS Error: {}", err.message(),)
        } else {
            println!(
                "\t OID_802_3_CURRENT_ADDRESS: {}",
                current_address_request.data
            )
        }

        if Ndisapi::is_ndiswan_ip(adapter.get_name())
            || Ndisapi::is_ndiswan_ipv6(adapter.get_name())
        {
            let mut ras_links_vec: Vec<RasLinks> = Vec::with_capacity(1);
            // SAFETY: ndisapi::RasLinks is too large to allocate memory on the stack and results in a stackoverflow error
            // Here is the workaround get a raw pointer to the vector with capacity to hold one ndisapi::RasLinks structure,
            // zero initialize the vector allocated memory and then set a vector length to one
            unsafe {
                write_bytes::<u8>(
                    mem::transmute::<*mut ndisapi::RasLinks, *mut u8>(ras_links_vec.as_mut_ptr()),
                    0,
                    size_of::<RasLinks>(),
                );
                ras_links_vec.set_len(1)
            };
            let ras_links = &mut ras_links_vec[0];

            if let Ok(()) = driver.get_ras_links(adapter.get_handle(), ras_links) {
                println!(
                    "Number of active WAN links: {}",
                    ras_links.get_number_of_links()
                );

                for k in 0..ras_links.get_number_of_links() {
                    println!(
                        "\t{}) LinkSpeed = {} MTU = {}",
                        k,
                        ras_links.ras_links[k].get_link_speed(),
                        ras_links.ras_links[k].get_maximum_total_size()
                    );

                    let local_mac_address =
                        MacAddress::from_slice(ras_links.ras_links[k].get_local_address()).unwrap();
                    let remote_mac_address =
                        MacAddress::from_slice(ras_links.ras_links[k].get_remote_address())
                            .unwrap();

                    println!("\t\tLocal MAC:\t {local_mac_address}");

                    println!("\t\tRemote MAC:\t {remote_mac_address}");

                    if Ndisapi::is_ndiswan_ip(adapter.get_name()) {
                        // Windows Vista and later offsets are used
                        println!(
                            "\t\tIP address:\t {}.{}.{}.{} mask {}.{}.{}.{}",
                            ras_links.ras_links[k].get_protocol_buffer()[584],
                            ras_links.ras_links[k].get_protocol_buffer()[585],
                            ras_links.ras_links[k].get_protocol_buffer()[586],
                            ras_links.ras_links[k].get_protocol_buffer()[587],
                            ras_links.ras_links[k].get_protocol_buffer()[588],
                            ras_links.ras_links[k].get_protocol_buffer()[589],
                            ras_links.ras_links[k].get_protocol_buffer()[590],
                            ras_links.ras_links[k].get_protocol_buffer()[591],
                        );
                    } else {
                        // IP v.6
                        println!(
                            "\t\tIPv6 address (without prefix):\t {:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}",
                            ras_links.ras_links[k].get_protocol_buffer()[588],
                            ras_links.ras_links[k].get_protocol_buffer()[589],
                            ras_links.ras_links[k].get_protocol_buffer()[590],
                            ras_links.ras_links[k].get_protocol_buffer()[591],
                            ras_links.ras_links[k].get_protocol_buffer()[592],
                            ras_links.ras_links[k].get_protocol_buffer()[593],
                            ras_links.ras_links[k].get_protocol_buffer()[594],
                            ras_links.ras_links[k].get_protocol_buffer()[595],
                        );
                    }
                }
            } else {
                println!("Failed to query active WAN links information.");
            }
        }
    }

    Ok(())
}

fn block(domains: &[String], driver: &Ndisapi, adapter: HANDLE) -> anyhow::Result<()> {
    let ips = resolve(domains)?;
    set_block_filters(driver, &ips)?;
    // Create a Win32 event for packet arrival notification
    let event: HANDLE;
    unsafe {
        event = CreateEventW(None, true, false, None)?;
    }

    // Set up a Ctrl-C handler to terminate the packet processing loop
    let terminate: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let ctrlc_pressed = terminate.clone();
    ctrlc::set_handler(move || {
        println!("Ctrl-C was pressed. Terminating...");
        // Set the atomic flag to exit the loop
        ctrlc_pressed.store(true, Ordering::SeqCst);
        // Signal the event to release the loop if there are no packets in the queue
        let _ = unsafe { SetEvent(event) };
    })
    .expect("Error setting Ctrl-C handler");

    // Set the event within the driver for packet arrival notification
    driver.set_packet_event(adapter, event)?;

    // Put the network interface into tunnel mode
    driver.set_adapter_mode(adapter, FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL)?;

    // Allocate a single IntermediateBuffer on the stack for packet reading
    let mut packet = IntermediateBuffer::default();

    // Start the packet processing loop
    while !terminate.load(Ordering::SeqCst) {
        // Wait for a packet to arrive
        unsafe {
            WaitForSingleObject(event, u32::MAX);
        }
        loop {
            // Initialize an EthRequestMut to pass to the driver API
            let mut read_request = EthRequestMut::new(adapter);

            // Set the packet buffer
            read_request.set_packet(&mut packet);

            // Read a packet from the network interface
            if driver.read_packet(&mut read_request).ok().is_none() {
                // No more packets in the queue, break the loop
                break;
            }

            // Get the direction of the packet
            let direction_flags = packet.get_device_flags();

            // Print packet information
            if direction_flags == DirectionFlags::PACKET_FLAG_ON_SEND {
                println!("\nMSTCP --> Interface ({} bytes)\n", packet.get_length());
            } else {
                println!("\nInterface --> MSTCP ({} bytes)\n", packet.get_length());
            }

            // Initialize an EthRequest to pass to the driver API
            let mut write_request = EthRequest::new(adapter);

            // Set the packet buffer
            write_request.set_packet(&packet);

            // Re-inject the packet back into the network stack
            if direction_flags == DirectionFlags::PACKET_FLAG_ON_SEND {
                // Send the packet to the network interface
                match driver.send_packet_to_adapter(&write_request) {
                    Ok(_) => {}
                    Err(err) => println!("Error sending packet to adapter. Error code = {err}"),
                };
            } else {
                // Send the packet to the TCP/IP stack
                match driver.send_packet_to_mstcp(&write_request) {
                    Ok(_) => {}
                    Err(err) => println!("Error sending packet to mstcp. Error code = {err}"),
                }
            }
        }

        // Reset the event to continue waiting for packets to arrive
        let _ = unsafe { ResetEvent(event) };
    }

    // Put the network interface back into default mode
    driver.set_adapter_mode(adapter, FilterFlags::default())?;

    // Close the event handle
    let _ = unsafe { CloseHandle(event) };
    Ok(())
}

fn set_block_filters(driver: &Ndisapi, ips: &[Ipv4Addr]) -> windows::core::Result<()> {
    let mut ips = ips.iter().copied();
    let mut filters: [_; 20] =
        std::array::from_fn(|_| ips.next().map(block_filter).unwrap_or_else(pass_filter));
    filters[19] = pass_filter();
    driver.set_packet_filter_table(&StaticFilterTable::<20>::from_filters(filters))
}

fn block_filter(ip: std::net::Ipv4Addr) -> StaticFilter {
    let [b1, b2, b3, b4] = ip.octets();
    StaticFilter::new(
        0,
        DirectionFlags::PACKET_FLAG_ON_SEND,
        FILTER_PACKET_DROP,
        FilterLayerFlags::NETWORK_LAYER_VALID | FilterLayerFlags::TRANSPORT_LAYER_VALID,
        DataLinkLayerFilter::default(),
        NetworkLayerFilter::new(
            IPV4,
            NetworkLayerFilterUnion {
                ipv4: IpV4Filter::new(
                    IpV4FilterFlags::IP_V4_FILTER_PROTOCOL
                        | IpV4FilterFlags::IP_V4_FILTER_DEST_ADDRESS,
                    IpAddressV4::default(),
                    IpAddressV4::new(
                        IP_SUBNET_V4_TYPE,
                        IpAddressV4Union {
                            ip_subnet: IpSubnetV4::new(
                                IN_ADDR {
                                    S_un: IN_ADDR_0 {
                                        S_un_b: IN_ADDR_0_0 {
                                            s_b1: b1,
                                            s_b2: b2,
                                            s_b3: b3,
                                            s_b4: b4,
                                        },
                                    },
                                },
                                IN_ADDR {
                                    S_un: IN_ADDR_0 {
                                        S_un_b: IN_ADDR_0_0 {
                                            s_b1: 255,
                                            s_b2: 255,
                                            s_b3: 255,
                                            s_b4: 255,
                                        },
                                    },
                                },
                            ),
                        },
                    ),
                    IPPROTO_TCP.0 as _,
                ),
            },
        ),
        TransportLayerFilter::new(
            TCPUDP,
            TransportLayerFilterUnion {
                tcp_udp: TcpUdpFilter::new(
                    TcpUdpFilterFlags::TCPUDP_DEST_PORT,
                    PortRange::default(),
                    PortRange::new(0, u16::MAX),
                    0u8,
                ),
            },
        ),
    )
}

fn pass_filter() -> StaticFilter {
    StaticFilter::new(
        0,
        DirectionFlags::PACKET_FLAG_ON_RECEIVE | DirectionFlags::PACKET_FLAG_ON_SEND,
        FILTER_PACKET_PASS,
        FilterLayerFlags::empty(),
        DataLinkLayerFilter::default(),
        NetworkLayerFilter::default(),
        TransportLayerFilter::default(),
    )
}
