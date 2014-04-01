#include <memcached-udp.hh>

#include <sys/cdefs.h>

#include <sys/types.h>
#include <osv/types.h>

#include <bsd/sys/net/ethernet.h>
#include <bsd/sys/net/if_types.h>
#include <bsd/sys/sys/param.h>

#include <bsd/sys/net/ethernet.h>
#include <bsd/sys/net/if_vlan_var.h>
#include <bsd/sys/netinet/in.h>
#include <bsd/sys/netinet/ip.h>
#include <bsd/sys/netinet/udp.h>

#include <bsd/sys/netinet/ip_var.h>
#include <bsd/sys/netinet/udp_var.h>

#include <machine/in_cksum.h>


namespace osv_apps {

//static u64 bucket_count;
/**
 * TODO:
 *  1) Get rid of C-string handling.
 *  2) Rearrange the code to be more structured.
 *  3) Add missing verbs.
 *
 * @param packet Pointer to the memcache data
 * @param len    Size of the memcache data
 */
int memcached::process_request(char* packet, u16 len)
{
    memcached_header* header = reinterpret_cast<memcached_header*>(packet);
    size_t hdr_len = sizeof(memcached_header);

    if ((len < hdr_len) || memcached_header_invalid(header)) {
        // Cannot send reply, have no sequence number to reply to..
        std::cerr << "unknown packet format. len=" << len << "\n";
        return -1;
    }
    len -= hdr_len;
    packet += hdr_len;

    // TODO: consider a more efficient parser...
    const char *p = packet, *pastend = packet + len;
    while (*p != ' ' && *p != '\r' && p < pastend) {
        p++;
    }
    auto n = p - packet;
    if (p == pastend) {
        return hdr_len + send_cmd_error(packet);
    }
    if (n == 3) {
        if(!strncmp(packet, "get", 3)) {
            //std::cerr<<"got 'get'\n";
            char key[251];
            // TODO: do this in a loop to support multiple keys on one command
            auto z = sscanf(packet + 4, "%250s", &key);
            if (z != 1) {
                return hdr_len + send_cmd_error(packet);
            }
            // TODO: do we need to copy the string just for find???
            // Need to be able to search without copy... HOW?

            char* reply = packet;
            char *r = reply + 6;
            std::string str_key(key);

            WITH_LOCK(_locked_shrinker) {
                auto it = _cache.find(str_key);

                if (it == _cache.end()) {
                    return hdr_len + send_cmd_end(packet);
                }

                //std::cerr << "found\n";
                strcpy(reply, "VALUE ");

                strcpy(r, str_key.c_str());
                r += str_key.size();

                int data_len = it->second.data.length();
                r += sprintf(r, " %ld %d\r\n", it->second.flags, data_len);

                // Value
                memcpy(r, it->second.data.c_str(), data_len);
                r += data_len;

                strcpy(r, "\r\nEND\r\n");
                r += 7;

                // Move the key to the front of the LRU
                move_to_lru_front(it);
            }

            return hdr_len + (r - reply);
        } else if(!strncmp(packet, "set", 3)) {
            //std::cerr<<"got 'set'\n";
            unsigned long flags, exptime, bytes;
            size_t end;
            char key[251];
            auto z =
              sscanf(packet+4, "%250s %ld %ld %ld%n",
                               &key, &flags, &exptime, &bytes, &end);

            end &= 0xffffffff;

            if (z != 4) {
                return hdr_len + send_cmd_error(packet);
            }
            // TODO: check if there is "noreply" at 'end'
            if (len < 4 + end + 2 + bytes) {
                std::cerr << "got too small packet ?! len="<<len<<", end="
                    <<end<<", bytes="<<bytes<<"\n";
                return hdr_len + send_cmd_error(packet);
            }

            std::string str_key(key);
            std::string str_val(packet + 4 + end + 2, bytes);

            u32 memory_needed = entry_mem_footprint(bytes, str_key.size());

            WITH_LOCK(_locked_shrinker) {
                auto it = _cache.find(str_key);

                // If it's a new key - add it to the lru
                if (it == _cache.end()) {
                    lru_entry* entry = new lru_entry(str_key);
                    _cache_lru.push_front(*entry);

                    _cache[str_key] =   { _cache_lru.begin(),
                                          str_val,
                                          (u32)flags,
                                          (time_t)exptime
                                        };

                    entry->mem_size = memory_needed;

                    #if 0
                    if (bucket_count !=  _cache.bucket_count()) {
                        bucket_count =  _cache.bucket_count();
                        printf("bucket number is %d\n", bucket_count);
                    }
                    #endif

                } else {
                    _cached_data_size -= it->second.lru_link->mem_size;

                    it->second.lru_link->mem_size = memory_needed;

                    // Update the cache value
                    it->second.data = str_val;
                    it->second.flags = (u32)flags;
                    it->second.exptime = (time_t)exptime;

                    // Move the key to the front of the LRU
                    move_to_lru_front(it, true);
                }
            }

            _cached_data_size += memory_needed;

            //std::cerr<<"got set with " << bytes << " bytes\n";
            return hdr_len + send_cmd_stored(packet);
        }
    }

    std::cerr<<"Error... Got "<<packet<<"\n";

    return hdr_len + send_cmd_error(packet);
}

void memcached::reverse_direction(mbuf* m, ether_header* ether_hdr, ip* ip_hdr,
                                  u16 ip_hlen, udphdr* udp_hdr, u16 data_len)
{
    // Ethernet: Swap MACs
    u_char	ether_addr[ETHER_ADDR_LEN * 2];
    memcpy(ether_addr, ether_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(ether_addr + ETHER_ADDR_LEN, ether_hdr->ether_dhost, ETHER_ADDR_LEN);
    memcpy(ether_hdr->ether_dhost, ether_addr, ETHER_ADDR_LEN * 2);

    // IP: Update total length
    ip_hdr->ip_len = htons(ip_hlen + sizeof(udphdr) + data_len);

    // IP: Restore the ip_off field - it's fucked in the ip_preprocess_packet()
    //     before PF hooks invocation.
    ip_hdr->ip_off = htons(ip_hdr->ip_off);

    // IP: Set TTL
    ip_hdr->ip_ttl = 0x40;

    // IP: Swap IPs
    in_addr ip_addr[2];
    memcpy(ip_addr, &ip_hdr->ip_dst, sizeof(in_addr));
    memcpy(ip_addr + 1, &ip_hdr->ip_src, sizeof(in_addr));
    memcpy(&ip_hdr->ip_src, ip_addr, sizeof(in_addr) * 2);

    // IP: Reset CSUM
    ip_hdr->ip_sum = 0;

    u16 csum = in_cksum(m, ip_hlen);

    ip_hdr->ip_sum = csum;

    // UDP: Swap ports
    u16 udp_port[2];

    udp_port[0] = udp_hdr->uh_dport;
    udp_port[1] = udp_hdr->uh_sport;
    memcpy(&udp_hdr->uh_sport, udp_port, sizeof(udp_port));

    // UDP: Update length
    udp_hdr->uh_ulen = htons(sizeof(udphdr) + data_len);

    // UDP: Clear CSUM
    udp_hdr->uh_sum = 0;
}

bool memcached::filter(struct ifnet* ifn, mbuf* m)
{
    //
    // We are called at the IP level, therefore the mbuf has already been
    // adjusted to point to the IP header.
    //
    caddr_t h = m->m_hdr.mh_data;

    // First check that the frame is a IPv4 UDP frame
    if (unsigned(m->m_hdr.mh_len) < sizeof(ip)) {
        return false;
    }

    auto ether_hdr = reinterpret_cast<ether_header*> (h - ETHER_HDR_LEN);
    if (ntohs(ether_hdr->ether_type) != ETHERTYPE_IP) {
        return false;
    }

    struct ip* ip_hdr = reinterpret_cast<ip*>(h);
    unsigned ip_size = ip_hdr->ip_hl << 2;
    if (ip_size < sizeof(ip)) {
        return false;
    }
    if (ip_hdr->ip_p != IPPROTO_UDP) {
        return false;
    }

    h += ip_size;
    struct udphdr* udp_hdr = reinterpret_cast<udphdr*>(h);

    int data_len = process_request(h + sizeof(udphdr),
                              ntohs(ip_hdr->ip_len) - ip_size - sizeof(udphdr));

    if (data_len < 0) {
        return false;
    }

    // Set new mbuf len
    m->m_hdr.mh_len = ip_size + sizeof(udphdr) + data_len;

    reverse_direction(m, ether_hdr, ip_hdr, ip_size, udp_hdr, (u16)data_len);

    // Request UDP CSUM offload if avaliable
    if (ifn->if_hwassist & CSUM_UDP) {
        m->M_dat.MH.MH_pkthdr.csum_flags = CSUM_UDP;
        m->M_dat.MH.MH_pkthdr.csum_data = offsetof(struct udphdr, uh_sum);
        udp_hdr->uh_sum = in_pseudo(ip_hdr->ip_src.s_addr,
                                    ip_hdr->ip_dst.s_addr,
                                    htons((u_short)data_len +
                                          sizeof(udphdr) + IPPROTO_UDP));
    } else {
        m->M_dat.MH.MH_pkthdr.csum_flags = 0;
    }

    // Adjust the mbuf to point to the ethernet header
    m->m_hdr.mh_data -= ETHER_HDR_LEN;
	m->m_hdr.mh_len  += ETHER_HDR_LEN;

	if (m->m_hdr.mh_flags & M_PKTHDR)
		m->M_dat.MH.MH_pkthdr.len += ETHER_HDR_LEN;

    ifn->if_transmit(ifn, m);

    //
    // If we have got here - the mbuf has already been handled:
    //  - if transmission has succeeded - GREAT!!!
    //  - if transmission has failed - it has been freed and stack has nothing
    //    to do with it anyway.
    //
    //  So we return "true" in both cases.
    //
    return true;
}

u64 memcached::shrink_cache_locked(size_t n)
{
    auto it = _cache_lru.end();
    u64 water_mark = (_cached_data_size / 10) * 9;
    u64 to_release = _cached_data_size - water_mark;
    u64 released_amount = 0;

    to_release = MAX(to_release, n);

    // Delete from the cache
    for (--it; released_amount < to_release; --it) {
        auto c_it = _cache.find(it->key);
        DEBUG_ASSERT(c_it != _cache.end(),
                     "Haven't found a cache entry for key [%s] "
                     "from the LRU list\n",
                     it->key.c_str());

        released_amount += it->mem_size;
        _cache.erase(c_it);
    }

    // Delete from the LRU list
    _cache_lru.erase_and_dispose(++it, _cache_lru.end(),
                                 delete_disposer());

    _cached_data_size -= released_amount;

    //printf("Released %ld bytes\n", released_amount);

    return released_amount;
}

void memcached::move_to_lru_front(cache_iterator& it, bool force)
{
    auto link_ptr = &it->second.lru_link;
    auto entry_ptr = &(*(*link_ptr));

    //  Move the key to the front if it's not already there
    if (*link_ptr != _cache_lru.begin()) {
        auto now = oc::uptime::now();

        if (force || ((now - entry_ptr->time).count() >
                                                     lru_update_interval)) {

            _cache_lru.erase(*link_ptr);
            _cache_lru.push_front(*entry_ptr);
            *link_ptr = _cache_lru.begin();
            entry_ptr->time = now;
        }
    }
}

} // namespace osv_apps

