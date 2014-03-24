#ifndef MEMCACHED_UDP_HH_
#define MEMCACHED_UDP_HH_

#include <sys/cdefs.h>
#include <bsd/porting/netport.h>
#include <bsd/sys/net/if_var.h>
#include <bsd/sys/net/if.h>
#include <bsd/sys/sys/mbuf.h>


#include <sys/types.h>
#include <osv/types.h>
#include <osv/debug.hh>

#include <bsd/sys/net/ethernet.h>
#include <bsd/sys/net/if_types.h>
#include <bsd/sys/sys/param.h>

#include <bsd/sys/net/ethernet.h>
#include <bsd/sys/netinet/in.h>
#include <bsd/sys/netinet/ip.h>
#include <bsd/sys/netinet/udp.h>
#include <bsd/sys/netinet/tcp.h>

#include <bsd/sys/netinet/ip_var.h>
#include <bsd/sys/netinet/udp_var.h>


#include <iostream>
#include <unordered_map>


namespace osv_apps {

class memcached {
public:
    //
    // Note: protocol specifies the key as limited to 250 bytes, no spaces or
    // control chars.
    //
    typedef std::string memcache_key;

    typedef std::list<memcache_key>                          lru_type;
    typedef lru_type::iterator                               lru_iterator;

    struct memcache_value {
        lru_iterator lru_link;
        std::string data;
        //
        // "flags" is an opaque 32-bit integer which the clients gives in the
        // "set" command, and is echoed back on "get" commands.
        //
        u32 flags;
        time_t exptime;
    };

    typedef std::unordered_map<memcache_key, memcache_value> cache_type;
    typedef cache_type::iterator                             cache_iterator;

    memcached(u64 max_cache_size) :
        _htons_1(ntohs(1)),
        _max_cache_size(max_cache_size),
        _cached_data_size(0) {}

    bool filter(struct ifnet* ifn, mbuf* m);
private:
    // The first 8 bytes of each UDP memcached request is the following header,
    // composed of four 16-bit integers in network byte order:
    struct memcached_header {
        // request_id is an opaque value that the server needs to echo back
        // to the client.
        u16 request_id;
        // If the request or response spans n datagrams, number_of_datagrams
        // contains n, and sequence_number goes from 0 to n-1.
        // Memcached does not currently support multi-datagram requests, so
        // neither do we have to. Memcached does support multi-datagram responses,
        // but the documentation suggest that TCP is more suitable for this
        // use case anyway, so we don't support this case as well.
        // This means we can always reuse a request header as the response header!
        u16 sequence_number_n;
        u16 number_of_datagrams_n;
        // Reserved for future use, should be 0
        u16 reserved;
    };

    /**
     * Parse and handle memcache request.
     * @param packet Pointer to the memcache data
     * @param len    Size of the memcache data
     */
    int process_request(char* packet, u16 len);

    /**
     * Prepare the packet to be sent back: reverse the addressing
     * @param m           buffer handle (points to the IP header)
     * @param ether_hdr   pointer to the Ethernet header
     * @param ip_hdr      pointer to the IPv4 header
     * @param ip_hlen     size of IPv4 header
     * @param udp_hdr     pointer to the UDP header
     * @param data_len    size of memcache data
     */
    void reverse_direction(mbuf* m, ether_header* ether_hdr, ip* ip_hdr,
                           u16 ip_hlen, udphdr* udp_hdr, u16 data_len);

    int send_cmd_error(char* packet) {
        constexpr char msg[] = "ERROR\r\n";

        memcpy(packet, msg, sizeof(msg) - 1);

        return sizeof(msg) - 1;
    }

    int send_cmd_stored(char* packet) {
        constexpr static char msg[] = "STORED\r\n";

        memcpy(packet, msg, sizeof(msg) - 1);

        return sizeof(msg) - 1;
    }

    int send_cmd_end(char* packet) {
        constexpr static char msg[] = "END\r\n";

        memcpy(packet, msg, sizeof(msg) - 1);

        return sizeof(msg) - 1;
    }

    bool memcached_header_invalid(memcached_header* hdr)
    {
        return (hdr->sequence_number_n != 0) ||
               (hdr->number_of_datagrams_n != _htons_1);
        // Could have also checked reserved !=0, but memaslap actually sets
        // it to 1...
    }

    /**
     * Shrink the cache to be at most 90% of the maximum allowed size after the
     * new value is added to it.
     *
     * @param new_data_len size of the new value to be stored in the cache
     */
    void shrink_cache(u16 new_data_len)
    {
        auto it = _cache_lru.end();
        u64 water_mark = (_max_cache_size / 10) * 9 - new_data_len;

        // Delete from the cache
        for (--it; _cached_data_size > water_mark; --it) {
            auto c_it = _cache.find(*it);
            DEBUG_ASSERT(c_it != _cache.end(),
                         "Haven't found a cache entry for key [%s] "
                         "from the LRU list\n",
                         it->c_str());

            _cached_data_size -= c_it->second.data.size();
            _cache.erase(c_it);
        }

        // Delete from the LRU list
        _cache_lru.erase(++it, _cache_lru.end());
    }

    void move_to_lru_front(cache_iterator& it, memcache_key& str_key)
    {
        // Move the key to the front if it's not already there
        if (it->second.lru_link != _cache_lru.begin()) {
            _cache_lru.erase(it->second.lru_link);
            _cache_lru.push_front(str_key);
            it->second.lru_link = _cache_lru.begin();
        }
    }

    void dump_mbuf(mbuf* m)
    {
        int i, j, len = m->m_hdr.mh_len;
        u8* data = (u8*)m->m_hdr.mh_data;

        for (i = 0; i < len; i += 16) {
            printf("%02x: ", i);
            for (j = 0; j < 16 && j + i < len; j++) {
                printf("%02x ", data[j + i]);
            }
            printf("\n");
        }
    }



private:
    const u16 _htons_1;
    u64 _max_cache_size;
    u64 _cached_data_size;

    cache_type _cache;

    /**
     * LRU keys list: the most rececently used at the front.
     */
    lru_type _cache_lru;
};

}

#endif /* MEMCACHED_UDP_HH_ */
