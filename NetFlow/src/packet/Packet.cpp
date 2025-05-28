#include "netflow/packet/Packet.h" // Already includes PacketBuffer, ethernet.h, ip.h, VlanTag, TcpHeader, UdpHeader
#include "netflow/protocols/arp.h" // For ArpHeader, needed for parsing, specifically its size
#include <cstring>                 // For memcpy, memmove
#include <arpa/inet.h>             // For ntohs, htons, ntohl, htonl
#include <iostream>                // For debugging (optional, can be removed for production)
#include <algorithm>               // For std::max

// Packet class is in global namespace as per Packet.h

Packet::Packet(PacketBuffer* buf)
    : buffer_(buf),
      head_data_ptr_(nullptr),
      current_length_(0),
      owns_buffer_(false),
      l3_offset_(-1),
      l4_offset_(-1),
      actual_ethertype_(0),
      has_vlan_tag_(false) {
  if (buffer_ && buffer_->data()) { // Ensure buffer and its data are valid
    head_data_ptr_ = reinterpret_cast<unsigned char*>(buffer_->data());
    current_length_ = buffer_->data_len();
    parse_packet();
  } else {
    // Handle null or invalid buffer case: Packet remains in a "null" or "empty" state.
    buffer_ = nullptr; // Ensure buffer_ is null if it was invalid.
    // All other members are already initialized to a safe state.
    // std::cerr << "Packet Warning: Constructed with null or invalid PacketBuffer." << std::endl;
  }
}

Packet::Packet(const void* data, size_t len, size_t buffer_size_to_alloc)
    : buffer_(nullptr), 
      head_data_ptr_(nullptr),
      current_length_(len),
      owns_buffer_(true), // This constructor owns the buffer
      l3_offset_(-1),
      l4_offset_(-1),
      actual_ethertype_(0),
      has_vlan_tag_(false) {
  if (!data && len > 0) {
      // std::cerr << "Packet Error: Constructed with non-zero length but null data pointer." << std::endl;
      current_length_ = 0; // Correct the state to be consistent.
      // Buffer will be allocated below, but it will be empty.
  }
  
  size_t alloc_size = std::max(len, buffer_size_to_alloc);
  // Ensure a minimum allocation size if len and buffer_size_to_alloc are both 0, to avoid zero-size new.
  if (alloc_size == 0) alloc_size = 1; 

  buffer_ = new PacketBuffer(alloc_size);
  if (buffer_ && buffer_->data()) { // Check if buffer allocation was successful
    head_data_ptr_ = reinterpret_cast<unsigned char*>(buffer_->data());
    if (data && current_length_ > 0) { // current_length_ might have been set to 0 if data was null
        std::memcpy(head_data_ptr_, data, current_length_);
    }
    buffer_->set_data_len(current_length_);
    parse_packet();
  } else {
      // std::cerr << "Packet Error: Buffer allocation failed in constructor." << std::endl;
      if(buffer_) {
          delete buffer_;
          buffer_ = nullptr;
      }
      owns_buffer_ = false; 
      current_length_ = 0; 
      head_data_ptr_ = nullptr;
  }
}

Packet::~Packet() {
  if (owns_buffer_ && buffer_) {
    delete buffer_;
    buffer_ = nullptr;
  }
}

void Packet::parse_packet() {
  // Reset parsed state
  l3_offset_ = -1;
  l4_offset_ = -1;
  actual_ethertype_ = 0;
  has_vlan_tag_ = false;

  if (!head_data_ptr_ || current_length_ < sizeof(netflow::packet::EthernetHeader)) {
    return; // Not enough data for even an Ethernet header
  }

  netflow::packet::EthernetHeader* eth_h = 
      reinterpret_cast<netflow::packet::EthernetHeader*>(head_data_ptr_);
  
  uint16_t current_ethertype_net = eth_h->type; // Network byte order
  size_t current_offset = sizeof(netflow::packet::EthernetHeader);

  if (ntohs(current_ethertype_net) == netflow::packet::VLAN_TPID) {
    if (current_length_ < current_offset + sizeof(netflow::packet::VlanTag)) {
      return; // Not enough data for VLAN tag
    }
    has_vlan_tag_ = true;
    netflow::packet::VlanTag* vlan_h = 
        reinterpret_cast<netflow::packet::VlanTag*>(head_data_ptr_ + current_offset);
    current_ethertype_net = vlan_h->ethertype; 
    current_offset += sizeof(netflow::packet::VlanTag);
  }
  
  actual_ethertype_ = ntohs(current_ethertype_net); 
  l3_offset_ = current_offset; 

  if (actual_ethertype_ == netflow::packet::ETHERTYPE_IP) {
    if (current_length_ < static_cast<size_t>(l3_offset_) + sizeof(netflow::packet::IpHeader)) { // Min IP header size
      l3_offset_ = -1; 
      return;
    }
    netflow::packet::IpHeader* ip_h = 
        reinterpret_cast<netflow::packet::IpHeader*>(head_data_ptr_ + l3_offset_);

    if (ip_h->version != 4) { 
        l3_offset_ = -1; 
        return;
    }
    
    uint8_t ip_header_len_bytes = ip_h->ihl * 4; 
    if (ip_header_len_bytes < sizeof(netflow::packet::IpHeader)) { 
        l3_offset_ = -1; 
        return;
    }

    if (current_length_ < static_cast<size_t>(l3_offset_) + ip_header_len_bytes) {
      l3_offset_ = -1; 
      return;
    }
    
    l4_offset_ = l3_offset_ + ip_header_len_bytes;
    
    // Check against total length field in IP header
    uint16_t ip_total_len_host = ntohs(ip_h->tot_len);
    if (current_length_ < static_cast<size_t>(l3_offset_) + ip_total_len_host) {
        // Packet is truncated compared to what IP header says.
        // We parsed what we have, but l4_offset might point outside current_length_ 
        // or to incomplete L4 data if ip_total_len_host was used to determine L4 boundary.
        // For now, continue parsing based on current_length_ for safety.
        // If L4 offset is beyond current_length, accessors will fail.
        if (static_cast<size_t>(l4_offset_) > current_length_) {
            l4_offset_ = -1; // L4 header cannot start beyond current packet data
        }
    }

  } else if (actual_ethertype_ == netflow::packet::ETHERTYPE_ARP) {
    if (current_length_ < static_cast<size_t>(l3_offset_) + sizeof(netflow::protocols::arp::ArpHeader)) {
      l3_offset_ = -1; 
      return;
    }
    // ARP does not have an L4, so l4_offset_ remains -1
  } else {
    l3_offset_ = -1; // Unknown L3 protocol, cannot proceed further.
  }
}


PacketBuffer* Packet::get_buffer() const { return buffer_; }
unsigned char* Packet::head() const { return head_data_ptr_; }
size_t Packet::length() const { return current_length_; }

void Packet::set_length(size_t len) {
  if (buffer_ && len <= buffer_->capacity()) { // Ensure new length is within buffer capacity
    current_length_ = len;
    buffer_->set_data_len(len);
    parse_packet(); // Re-parse with the new length
  } else if (buffer_ && len > buffer_->capacity()) {
    // std::cerr << "Packet Error: New length " << len << " exceeds buffer capacity " << buffer_->capacity() << std::endl;
    // Option: reallocate buffer if owned, or simply fail. For now, fail.
  } else if (!buffer_) {
    // std::cerr << "Packet Error: Cannot set length, buffer is null." << std::endl;
  }
}

netflow::packet::EthernetHeader* Packet::ethernet() const {
    if (!head_data_ptr_ || current_length_ < sizeof(netflow::packet::EthernetHeader)) return nullptr;
    // The problem description for Packet.h specified ethernet(size_t offset = 0).
    // This is unusual for a specific header accessor. Assuming offset is always 0 for the primary eth header.
    return reinterpret_cast<netflow::packet::EthernetHeader*>(head_data_ptr_);
}

netflow::packet::VlanTag* Packet::vlan_tag_header() const {
    if (!has_vlan_tag_ || !head_data_ptr_ || 
        current_length_ < (sizeof(netflow::packet::EthernetHeader) + sizeof(netflow::packet::VlanTag))) {
        return nullptr;
    }
    return reinterpret_cast<netflow::packet::VlanTag*>(head_data_ptr_ + sizeof(netflow::packet::EthernetHeader));
}

netflow::packet::IpHeader* Packet::ipv4() const {
    if (l3_offset_ == -1 || actual_ethertype_ != netflow::packet::ETHERTYPE_IP || !head_data_ptr_) {
        return nullptr;
    }
    // Check if minimal IpHeader is present
    if (current_length_ < static_cast<size_t>(l3_offset_) + sizeof(netflow::packet::IpHeader)) { 
        return nullptr;
    }
    netflow::packet::IpHeader* ip_h = reinterpret_cast<netflow::packet::IpHeader*>(head_data_ptr_ + l3_offset_);
    // Check against IHL
    uint8_t ip_header_len_bytes = ip_h->ihl * 4;
    if (current_length_ < static_cast<size_t>(l3_offset_) + ip_header_len_bytes) {
        return nullptr; 
    }
    return ip_h;
}

netflow::packet::TcpHeader* Packet::tcp() const {
    auto ip_h = ipv4(); // This already checks l3_offset, ethertype, and basic IP header validity
    if (!ip_h || ip_h->protocol != netflow::packet::IPPROTO_TCP || l4_offset_ == -1 || !head_data_ptr_) {
        return nullptr;
    }
    // Check if minimal TcpHeader is present
    if (current_length_ < static_cast<size_t>(l4_offset_) + sizeof(netflow::packet::TcpHeader)) { 
        return nullptr;
    }
    netflow::packet::TcpHeader* tcp_h = reinterpret_cast<netflow::packet::TcpHeader*>(head_data_ptr_ + l4_offset_);
    // Check against data offset
    uint8_t tcp_header_len_bytes = tcp_h->get_data_offset_bytes();
    if (current_length_ < static_cast<size_t>(l4_offset_) + tcp_header_len_bytes) {
        return nullptr; 
    }
    return tcp_h;
}

netflow::packet::UdpHeader* Packet::udp() const {
    auto ip_h = ipv4();
    if (!ip_h || ip_h->protocol != netflow::packet::IPPROTO_UDP || l4_offset_ == -1 || !head_data_ptr_) {
        return nullptr;
    }
    if (current_length_ < static_cast<size_t>(l4_offset_) + sizeof(netflow::packet::UdpHeader)) {
        return nullptr;
    }
    return reinterpret_cast<netflow::packet::UdpHeader*>(head_data_ptr_ + l4_offset_);
}

bool Packet::has_vlan() const { return has_vlan_tag_; }

uint16_t Packet::vlan_id() const {
    if (!has_vlan_tag_) return 0;
    auto vth = vlan_tag_header(); // This already checks length and has_vlan_tag_ implicitly
    return vth ? vth->get_vlan_id() : 0; 
}

uint8_t Packet::vlan_priority() const {
    if (!has_vlan_tag_) return 0;
    auto vth = vlan_tag_header();
    return vth ? vth->get_priority_code_point() : 0;
}

std::array<uint8_t, 6> Packet::src_mac() const {
    auto eth_h = ethernet();
    return eth_h ? eth_h->src_mac : std::array<uint8_t, 6>{};
}

std::array<uint8_t, 6> Packet::dst_mac() const {
    auto eth_h = ethernet();
    return eth_h ? eth_h->dest_mac : std::array<uint8_t, 6>{};
}

uint16_t Packet::get_actual_ethertype() const {
    return actual_ethertype_; // Already in host byte order from parse_packet()
}

uint32_t Packet::get_src_ip() const {
    auto ip_h = ipv4();
    return ip_h ? ntohl(ip_h->saddr) : 0;
}

uint32_t Packet::get_dst_ip() const {
    auto ip_h = ipv4();
    return ip_h ? ntohl(ip_h->daddr) : 0;
}

uint8_t Packet::get_ip_protocol() const {
    auto ip_h = ipv4();
    return ip_h ? ip_h->protocol : 0;
}

uint16_t Packet::get_src_port() const {
    if (auto ip_h = ipv4()) { // Ensure it's an IP packet first
        if (ip_h->protocol == netflow::packet::IPPROTO_TCP) {
            if (auto tcp_h = tcp()) return ntohs(tcp_h->src_port);
        } else if (ip_h->protocol == netflow::packet::IPPROTO_UDP) {
            if (auto udp_h = udp()) return ntohs(udp_h->src_port);
        }
    }
    return 0;
}

uint16_t Packet::get_dst_port() const {
     if (auto ip_h = ipv4()) {
        if (ip_h->protocol == netflow::packet::IPPROTO_TCP) {
            if (auto tcp_h = tcp()) return ntohs(tcp_h->dst_port);
        } else if (ip_h->protocol == netflow::packet::IPPROTO_UDP) {
            if (auto udp_h = udp()) return ntohs(udp_h->dst_port);
        }
    }
    return 0;
}

bool Packet::set_dst_mac(const std::array<uint8_t, 6>& new_dst_mac) {
    auto eth_h = ethernet();
    if (eth_h) {
        eth_h->dest_mac = new_dst_mac;
        return true;
    }
    return false;
}

bool Packet::set_src_mac(const std::array<uint8_t, 6>& new_src_mac) {
    auto eth_h = ethernet();
    if (eth_h) {
        eth_h->src_mac = new_src_mac;
        return true;
    }
    return false;
}

void Packet::update_checksums() {
    // Placeholder: Actual checksum calculation is complex and depends on what changed.
    // For example, IP checksum needs recalculation if any IP header field changes.
    // TCP/UDP checksums involve pseudo-header and payload.
    // std::cout << "Packet::update_checksums() called - NOT IMPLEMENTED" << std::endl;
}

void Packet::update_ip_checksum() {
    netflow::packet::IpHeader* ip_h = ipv4(); // ipv4() gets the IpHeader pointer
    if (ip_h) {
        ip_h->check = 0; // Zero out checksum field before calculation
        // calculate_ip_header_checksum expects a const IpHeader*.
        // It's okay to cast from non-const to const for this call.
        ip_h->check = netflow::packet::calculate_ip_header_checksum(static_cast<const netflow::packet::IpHeader*>(ip_h));
    }
}

bool Packet::push_vlan(uint16_t tci_val_host_order) {
    // Pre-conditions:
    if (has_vlan_tag_) { // No double tagging for now
        // std::cerr << "Packet Error: push_vlan - Packet already has a VLAN tag." << std::endl;
        return false;
    }
    if (buffer_ == nullptr || head_data_ptr_ == nullptr) {
        // std::cerr << "Packet Error: push_vlan - Buffer or head_data_ptr is null." << std::endl;
        return false;
    }
    if (current_length_ < sizeof(netflow::packet::EthernetHeader)) {
        // std::cerr << "Packet Error: push_vlan - Packet too short for Ethernet header." << std::endl;
        return false;
    }
    // Check if there's enough space in the buffer to add a VLAN tag.
    // buffer_->size() is the total capacity of the underlying PacketBuffer's memory block.
    if (current_length_ + sizeof(netflow::packet::VlanTag) > buffer_->size()) {
        // std::cerr << "Packet Error: push_vlan - Not enough space in buffer to add VLAN tag." << std::endl;
        return false;
    }

    // Logic:
    netflow::packet::EthernetHeader* eth_hdr = ethernet(); // Should be valid due to checks above
    if (!eth_hdr) return false; // Should not happen if above checks pass

    uint16_t original_ethertype_net = eth_hdr->type; // Already in network byte order

    // Position where VLAN tag starts (this is where the original EtherType was).
    // offsetof(netflow::packet::EthernetHeader, type) is 12 bytes.
    unsigned char* vlan_tag_insertion_point = head_data_ptr_ + (2 * 6); // Offset of eth_hdr->type

    // Start of L3 data (payload after original EtherType field in EthernetHeader)
    unsigned char* l3_data_start = head_data_ptr_ + sizeof(netflow::packet::EthernetHeader);
    
    // Length of data to be shifted (everything after the original Ethernet header's src/dst MACs and type field)
    size_t data_to_shift_len = current_length_ - sizeof(netflow::packet::EthernetHeader);

    // Shift L3 data and everything after it to the right by sizeof(VlanTag)
    // Target: l3_data_start + sizeof(netflow::packet::VlanTag)
    // Source: l3_data_start
    // Length: data_to_shift_len
    // Note: The operation is effectively making space for the VlanTag right after the MAC addresses.
    // The original eth_hdr->type field will be overwritten by the start of the VlanTag.
    // So, we shift the content starting from eth_hdr->type.
    unsigned char* original_ethertype_location = head_data_ptr_ + offsetof(netflow::packet::EthernetHeader, type);
    size_t actual_data_to_shift_len = current_length_ - offsetof(netflow::packet::EthernetHeader, type);


    if (actual_data_to_shift_len > 0) { // only move if there's something to move
        memmove(original_ethertype_location + sizeof(netflow::packet::VlanTag), 
                original_ethertype_location, 
                actual_data_to_shift_len);
    }


    // Update Ethernet header's EtherType to VLAN TPID
    eth_hdr->type = htons(netflow::packet::VLAN_TPID);

    // Construct the VLAN tag at vlan_tag_insertion_point (which is now where eth_hdr->type was)
    // No, vlan_tag_insertion_point should be where the new VlanTag itself starts,
    // which is right after the MAC addresses. The original eth_hdr->type field is *part* of this.
    netflow::packet::VlanTag* new_tag = reinterpret_cast<netflow::packet::VlanTag*>(original_ethertype_location);
    new_tag->tci = htons(tci_val_host_order);
    new_tag->ethertype = original_ethertype_net; // original_ethertype_net is already network byte order

    // Update packet length
    current_length_ += sizeof(netflow::packet::VlanTag);
    buffer_->set_data_len(current_length_);

    // Call parse_packet() to update internal offsets and state
    parse_packet();

    return true;
}

bool Packet::pop_vlan() {
    // Pre-conditions:
    if (!has_vlan_tag_) { // Check internal state from parse_packet
        // std::cerr << "Packet Error: pop_vlan - Packet does not have a VLAN tag." << std::endl;
        return false;
    }
    if (buffer_ == nullptr || head_data_ptr_ == nullptr) {
        // std::cerr << "Packet Error: pop_vlan - Buffer or head_data_ptr is null." << std::endl;
        return false;
    }
    // This check also ensures EthernetHeader is present.
    if (current_length_ < sizeof(netflow::packet::EthernetHeader) + sizeof(netflow::packet::VlanTag)) {
        // std::cerr << "Packet Error: pop_vlan - Packet too short to contain Ethernet and VLAN header." << std::endl;
        return false;
    }

    // Logic:
    netflow::packet::EthernetHeader* eth_hdr = ethernet(); // Should be valid
    if (!eth_hdr) return false;

    // vlan_tag_header() relies on parse_packet having run and has_vlan_tag_ being true.
    // It returns a pointer to the VlanTag struct.
    netflow::packet::VlanTag* vlan_hdr = vlan_tag_header(); 
    if (vlan_hdr == nullptr) { // Should not happen if has_vlan_tag_ is true and length checks pass
        // std::cerr << "Packet Error: pop_vlan - vlan_tag_header returned null despite has_vlan_tag_ being true." << std::endl;
        // This might indicate an inconsistency or a bug in parse_packet or vlan_tag_header accessor.
        // For robustness, explicitly re-run parse_packet and try again or just fail.
        parse_packet(); // Attempt re-parse
        vlan_hdr = vlan_tag_header();
        if (vlan_hdr == nullptr) return false;
    }

    uint16_t inner_ethertype_net = vlan_hdr->ethertype; // Already network byte order

    // Start of the VLAN tag (which is where the new EtherType will be written)
    unsigned char* vlan_tag_start_ptr = reinterpret_cast<unsigned char*>(vlan_hdr);
    // This is effectively head_data_ptr_ + offsetof(netflow::packet::EthernetHeader, type)
    // or head_data_ptr_ + 12

    // Start of L3 data (payload after VLAN tag)
    unsigned char* l3_data_start_ptr = vlan_tag_start_ptr + sizeof(netflow::packet::VlanTag);

    // Length of data to be shifted (everything after the VLAN tag)
    // (head_data_ptr_ + current_length_) is one byte beyond the end of the packet data.
    // l3_data_start_ptr points to the first byte of data to be moved.
    size_t data_to_shift_len = (head_data_ptr_ + current_length_) - l3_data_start_ptr;

    // Shift L3 data to the left by sizeof(VlanTag), overwriting the VLAN tag.
    // Destination: vlan_tag_start_ptr
    // Source: l3_data_start_ptr
    if (data_to_shift_len > 0) { // only move if there's something to move
         memmove(vlan_tag_start_ptr, l3_data_start_ptr, data_to_shift_len);
    }
   

    // Update Ethernet header's EtherType
    // The vlan_tag_start_ptr is where the old vlan_hdr->tci was.
    // The eth_hdr->type is at this same location.
    eth_hdr->type = inner_ethertype_net; // inner_ethertype_net is already network byte order

    // Update packet length
    current_length_ -= sizeof(netflow::packet::VlanTag);
    buffer_->set_data_len(current_length_);

    // Call parse_packet() to update internal offsets and state
    parse_packet();

    return true;
}
