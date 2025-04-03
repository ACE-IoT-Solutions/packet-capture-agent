"""
Analytics module for the Packet Capture agent.

This module provides functions for analyzing BACnet packet captures (pcap files),
extracting network metrics, and generating performance scores. It's integrated
directly into the agent to avoid external dependencies.
"""

from collections import defaultdict
from typing import Any, Dict, Generator, List, Tuple, Union
import logging
import binascii

import netifaces as ni
from scapy.all import PcapReader
from .bp_analytics import decode_packet
from bacpypes.apdu import IAmRequest, WhoIsRequest
from bacpypes.debugging import xtob
from bacpypes.pdu import PDU, Address, GlobalBroadcast, LocalBroadcast, RemoteStation

_log = logging.getLogger(__name__)


def iterate_bacnet_packets(pcap_path: str) -> Generator:
    """Iterates through a pcap file and yields decoded BACnet packets.

    Args:
        pcap_path: Path to the PCAP file to process
    Yields:
        Decoded BACnet APDU objects with valid source and destination addresses
    """
    # Read the pcap file
    with PcapReader(pcap_path) as pcap_reader:
        # Decode packets using bacpypes
        for packet in pcap_reader:
            try:
                bp_apdu = decode_packet(packet.original)
                # Only yield packets with valid source and destination addresses
                if bp_apdu.pduSource and bp_apdu.pduDestination:
                    yield bp_apdu
            except Exception as e:
                # Skip packets that can't be processed
                _log.error(f"Error decoding packet: {e} data: {packet.original.hex()}")
                continue


def process_pcap(pcap_path: str, broadcast_addrs: List[str]) -> Dict[str, Any]:
    """Process a pcap file and return a dictionary of traffic statistics.

    This function analyzes a BACnet packet capture file and generates comprehensive statistics about
    the network traffic, including device relationships, message types, and broadcast patterns.

    Args:
        pcap_path: Path to the PCAP file to process
        broadcast_addrs: List of broadcast addresses to identify in the capture

    Returns:
        A dictionary containing various traffic statistics and device mappings:
        - traffic_counter: Counter for traffic between node pairs
        - traffic_type_counter: Counter for different BACnet message types
        - dest_type_counter: Counter for destination address types
        - broadcast_src: Counter for sources of broadcast messages
        - global_whois: Counter for global Who-Is requests by source
        - address_map: Mapping from BACnet addresses to device IDs
        - reverse_address_map: Mapping from device IDs to BACnet addresses
        - packet_count: Total number of valid packets processed
    """
    packet_count = 0
    
    # Initialize counters and mappings
    traffic_counter: Dict[Tuple[str, str], int] = defaultdict(
        int
    )  # Count traffic between source-destination pairs
    traffic_type_counter: Dict[str, int] = defaultdict(
        int
    )  # Count messages by BACnet message type
    dest_type_counter: Dict[str, int] = defaultdict(
        int
    )  # Count by destination type (broadcast, unicast, etc.)
    broadcast_src: Dict[str, int] = defaultdict(
        int
    )  # Track sources of broadcast messages
    global_whois: Dict[str, int] = defaultdict(
        int
    )  # Track sources of global Who-Is requests
    address_map = {}  # Map BACnet addresses to device IDs
    reverse_address_map = {}  # Map device IDs to BACnet addresses

    # Read the pcap file
    
    for bp_apdu in iterate_bacnet_packets(pcap_path):
        try:
            # Assemble and decode the packet
            src_addr = bp_apdu.pduSource
            dest_addr = bp_apdu.pduDestination
            packet_count += 1
        except Exception as e:
            continue

        # Process I-Am requests to build address maps
        if issubclass(bp_apdu.__class__, IAmRequest):
            # Map the BACnet address to the device ID
            address_map[str(bp_apdu.pduSource)] = bp_apdu.iAmDeviceIdentifier[1]
            reverse_address_map[bp_apdu.iAmDeviceIdentifier[1]] = str(
                bp_apdu.pduSource
            )

        # Identify and count global Who-Is requests
        if issubclass(bp_apdu.__class__, WhoIsRequest):
            # A global Who-Is has the full possible device range (0 to 4194303)
            if (
                bp_apdu.deviceInstanceRangeLowLimit == 0
                and bp_apdu.deviceInstanceRangeHighLimit == 4194303
            ):
                global_whois[str(bp_apdu.pduSource)] += 1

        # Count traffic between specific source-destination pairs
        traffic_counter[(str(src_addr), str(dest_addr))] += 1

        # Count by message type (class name)
        traffic_type_counter[bp_apdu.__class__.__name__] += 1

        # Categorize and count destination address types
        if issubclass(dest_addr.__class__, GlobalBroadcast):
            dest_type_counter[GlobalBroadcast.__name__] += 1
            broadcast_src[str(src_addr)] += 1  # Track broadcast sources
        elif issubclass(dest_addr.__class__, LocalBroadcast):
            dest_type_counter[LocalBroadcast.__name__] += 1
            broadcast_src[str(src_addr)] += 1  # Track broadcast sources
        elif issubclass(dest_addr.__class__, RemoteStation):
            dest_type_counter[RemoteStation.__name__] += 1
        elif (
            issubclass(dest_addr.__class__, Address)
            and str(dest_addr.addrBroadcastTuple[0]) in broadcast_addrs
        ):
            # Handle broadcasts using standard IP addresses
            dest_type_counter[LocalBroadcast.__name__] += 1
            broadcast_src[str(src_addr)] += 1  # Track broadcast sources
        else:
            dest_type_counter[dest_addr.__class__.__name__] += 1

    # Return comprehensive statistics dictionary
    return {
        "traffic_counter": traffic_counter,
        "traffic_type_counter": traffic_type_counter,
        "dest_type_counter": dest_type_counter,
        "broadcast_src": broadcast_src,
        "global_whois": global_whois,
        "address_map": address_map,
        "reverse_address_map": reverse_address_map,
        "packet_count": packet_count,
    }


def generate_scores(
    traffic_counter: Dict[Tuple[str, str], int],
    traffic_type_counter: Dict[str, int],
    dest_type_counter: Dict[str, int],
    global_whois: Dict[str, int],
) -> Dict[str, float]:
    """Takes a set of counters and scores the observed traffic based on BACnet best practices.

    This function evaluates BACnet network health by analyzing traffic patterns and calculating
    a score based on key metrics. Lower scores indicate potential issues with the network.

    Args:
        traffic_counter: Counter mapping source-destination pairs to packet counts
        traffic_type_counter: Counter mapping message types to packet counts
        dest_type_counter: Counter mapping destination types to packet counts
        global_whois: Counter mapping sources to global Who-Is request counts

    Returns:
        A dictionary containing the network score and component ratios:
        - total_score: Overall network health score (0-100)
        - local_broadcast_ratio: Ratio of local broadcast traffic
        - remote_station_ratio: Ratio of unicast (point-to-point) traffic
        - whois_ratio: Ratio of Who-Is/Who-Has discovery traffic
        - prop_acked_ratio: Read Property response success rate
        - props_acked_ratio: Read Property Multiple response success rate
    """
    # Start with a perfect score of 100
    score = 100.0

    # Calculate total traffic volume
    total_traffic = sum(traffic_counter.values())
    if total_traffic == 0:
        return {
            "total_score": 0.0,
            "local_broadcast_ratio": 0.0,
            "remote_station_ratio": 0.0,
            "whois_ratio": 0.0,
            "prop_acked_ratio": 0.0,
            "props_acked_ratio": 0.0,
        }

    # Calculate ratios of different address types
    global_broadcast_ratio = (
        dest_type_counter.get(GlobalBroadcast.__name__, 0) / total_traffic
    )
    local_broadcast_ratio = (
        dest_type_counter.get(LocalBroadcast.__name__, 0) / total_traffic
    )
    remote_station_ratio = (
        dest_type_counter.get(RemoteStation.__name__, 0) / total_traffic
    )

    # Calculate ratios for specific message types
    whois_ratio = (
        traffic_type_counter.get("WhoIsRequest", 0)
        + traffic_type_counter.get("WhoHasRequest", 0)
    ) / total_traffic

    # Calculate ratio of global Who-Is requests
    global_whois_ratio = (
        sum(global_whois.values()) / total_traffic if global_whois else 0
    )

    # Calculate response success rates for Read Property requests
    # Use 1 as default to avoid division by zero
    prop_requests = traffic_type_counter.get("ReadPropertyRequest", 0)
    prop_acks = traffic_type_counter.get("ReadPropertyACK", 0)
    prop_acked_ratio = prop_acks / prop_requests if prop_requests > 0 else 1.0

    # Calculate response success rates for Read Property Multiple requests
    props_requests = traffic_type_counter.get("ReadPropertyMultipleRequest", 0)
    props_acks = traffic_type_counter.get("ReadPropertyMultipleACK", 0)
    props_acked_ratio = props_acks / props_requests if props_requests > 0 else 1.0

    # Calculate average traffic per device pair
    device_traffic = total_traffic / len(traffic_counter) if traffic_counter else 0

    # Calculate total broadcast ratio (both global and local)
    broadcast_ratio = global_broadcast_ratio + local_broadcast_ratio

    # Apply scoring penalties based on network best practices

    # Penalize excessive broadcast traffic (should be below 1%)
    if broadcast_ratio > 0.01:
        score -= 5 + (10 * broadcast_ratio)

    # Penalize excessive discovery traffic (Who-Is/Who-Has should be below 1%)
    if whois_ratio > 0.01:
        score -= 5 + (10 * whois_ratio)

    # Heavily penalize global Who-Is requests (especially harmful)
    if global_whois_ratio > 0.01:
        score -= 10 + (20 * global_whois_ratio)

    # Penalize very chatty devices
    if device_traffic > 100:
        score -= 5 + ((device_traffic / 100))

    # Penalize poor Read Property response rates (should be above 98%)
    if prop_acked_ratio < 0.98:
        score -= 5 + (100 * (1 - prop_acked_ratio))

    # Penalize poor Read Property Multiple response rates (should be above 97%)
    if props_acked_ratio < 0.97:
        score -= 5 + (100 * (1 - props_acked_ratio))

    # Ensure score doesn't go below 0
    score = max(0, score)

    # Return the final score and component ratios
    return {
        "total_score": score,
        "local_broadcast_ratio": local_broadcast_ratio,
        "remote_station_ratio": remote_station_ratio,
        "whois_ratio": whois_ratio,
        "prop_acked_ratio": prop_acked_ratio,
        "props_acked_ratio": props_acked_ratio,
    }


def rank_broadcast(broadcast_src: Dict[str, int]) -> List[Tuple[str, int]]:
    """Sort broadcast sources by number of packets to identify top broadcast generators.

    Args:
        broadcast_src: Dictionary mapping source addresses to broadcast packet counts

    Returns:
        List of (source, count) tuples sorted in descending order by count
    """
    return sorted(broadcast_src.items(), key=lambda x: x[1], reverse=True)


def get_local_broadcast() -> List[str]:
    """Walks local network interfaces and collects all broadcast addresses.

    This function scans all network interfaces on the local machine and extracts
    the broadcast addresses for each interface with an IPv4 address assignment.

    Returns:
        List of broadcast address strings (e.g., ['192.168.1.255', '10.0.0.255'])
    """
    broadcast_addrs: List[str] = []

    # Iterate through all network interfaces
    for interface in ni.interfaces():
        # Get address information for each interface
        try:
            for index, addresses in ni.ifaddresses(interface).items():
                for address in addresses:
                    # Only consider addresses with both broadcast and netmask attributes (IPv4)
                    if "broadcast" in address and "netmask" in address:
                        broadcast_addrs.append(address["broadcast"])
        except Exception:
            # Skip interfaces that can't be processed
            continue

    return broadcast_addrs
