#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <sys/types.h>
#include <tins/tins.h>
#include <unordered_map>
#include <thread>
#include <chrono>

class arp_monitor {
public:
    void arp_entries(Tins::Sniffer& sniffer, int timeout_ms) {
        addresses.clear();
        m_sniff = true;
        std::thread timeout_thread([this, timeout_ms]{
            std::this_thread::sleep_for(std::chrono::milliseconds(timeout_ms));
            m_sniff = false;
        });
        run(sniffer);
        timeout_thread.join();
    }

    void run(Tins::Sniffer& sniffer)
    {
        sniffer.sniff_loop(std::bind(&arp_monitor::callback, this,
                                     std::placeholders::_1));
    }
private:
    bool callback(const Tins::PDU& pdu)
    {
        const Tins::ARP& arp = pdu.rfind_pdu<Tins::ARP>();

        if (arp.opcode() == Tins::ARP::REPLY) {
            auto iter = addresses.find(arp.sender_ip_addr());
            if (iter == addresses.end()) {
                addresses[arp.sender_ip_addr()] = arp.sender_hw_addr();
                std::cout << "[INFO] " << arp.sender_ip_addr() << " is at "
                          << arp.sender_hw_addr() << std::endl;
            } else {
                if (arp.sender_hw_addr() != iter->second) {
                    std::cout << "[WARNING] " << arp.sender_ip_addr()
                              << " is at " << iter->second << " but also at "
                              << arp.sender_hw_addr() << std::endl;
                }
            }
        }

        return m_sniff;
    }

    bool m_sniff = true;
    std::unordered_map<Tins::IPv4Address, Tins::HWAddress<6>> addresses;
};

uint32_t swap_endian(uint32_t value) {
    return ((value >> 24) & 0x000000FF) |
           ((value >> 8)  & 0x0000FF00) |
           ((value << 8)  & 0x00FF0000) |
           ((value << 24) & 0xFF000000);
}

uint32_t ipv4_to_int(const Tins::IPv4Address& ip) {
    return static_cast<uint32_t>(ip);
}

Tins::IPv4Address next(const Tins::IPv4Address& ip) {
    uint32_t ip_int = swap_endian(ip) + 1;
    return Tins::IPv4Address(swap_endian(ip_int));
}

void send_arp_requests(std::string interface_name, unsigned short requests_per_ip = 1)
{
    Tins::PacketSender sender;

    Tins::NetworkInterface interface(interface_name);
    auto interface_address = interface.ipv4_address();
    auto mask = interface.ipv4_mask();
    auto gateway_hw_address = interface.hw_address();

    auto network_address = interface_address & mask;
    auto broadcast_address = interface_address | (~mask);

    for (auto current_ip = next(network_address); current_ip < broadcast_address; current_ip = next(current_ip)) {
        Tins::ARP request(current_ip, interface_address, Tins::HWAddress<6>("ff:ff:ff:ff:ff:ff"), gateway_hw_address);
        request.opcode(Tins::ARP::REQUEST);
        Tins::EthernetII eth = Tins::EthernetII(Tins::HWAddress<6>("ff:ff:ff:ff:ff:ff"), gateway_hw_address) / request;

        for (unsigned short i = 0; i < requests_per_ip; ++i)
            sender.send(eth, interface);
    }
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        std::cerr << "Usage: " << *argv << " <interface>" << std::endl;
        return 1;
    }

    std::string interface_name = argv[1];
    arp_monitor monitor;
    Tins::SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_filter("arp");

    int num_arp_sweeps = 1;
    try {
        std::thread arp_sender([interface_name, num_arp_sweeps]{
            for (int i = 0; i < num_arp_sweeps; ++i)
                send_arp_requests(interface_name);
        });
        Tins::Sniffer sniffer(argv[1], config);
        monitor.arp_entries(sniffer, 1000);
        arp_sender.join();
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    return 0;
}