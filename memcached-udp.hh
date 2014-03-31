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
#include <osv/clock.hh>
#include <osv/ilog2.hh>
#include <osv/mempool.hh>

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

#include <boost/intrusive/list.hpp>

namespace bi = boost::intrusive;
namespace oc = osv::clock;
namespace osv_apps {

class memcached : public memory:: shrinker {
public:
    //
    // Note: protocol specifies the key as limited to 250 bytes, no spaces or
    // control chars.
    //
    typedef std::string memcache_key;

    struct lru_entry : public boost::intrusive::list_base_hook<> {
        memcache_key             key;
        oc::uptime::time_point   time;
        u32                      mem_size;

        lru_entry(std::string& k) : key(k), time(oc::uptime::now()), mem_size(0) {}
    };

    typedef bi::list<lru_entry>                                lru_type;
    typedef lru_type::iterator                                 lru_iterator;

    struct memcache_value {
        lru_iterator lru_link;
        std::string  data;
        //
        // "flags" is an opaque 32-bit integer which the clients gives in the
        // "set" command, and is echoed back on "get" commands.
        //
        u32          flags;
        time_t       exptime;
    };

    typedef std::unordered_map<memcache_key, memcache_value> cache_type;
    typedef cache_type::iterator                             cache_iterator;

    explicit memcached() : memory::shrinker("osv-memcached"),
        _htons_1(ntohs(1)),
        _cached_data_size(0) {}

    bool filter(struct ifnet* ifn, mbuf* m);

    size_t request_memory(size_t n)
    {
        return shrink_cache();
    }

    size_t release_memory(size_t n)
    {
        return 0;
    }

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

    //The disposer object function
    struct delete_disposer
    {
        void operator()(lru_entry* delete_this) { delete delete_this; }
    };

    /**
     * Shrink the cache by 10% of the current size.
     */
    u64 shrink_cache(void)
    {
        auto it = _cache_lru.end();
        u64 water_mark = (_cached_data_size / 10) * 9;
        u64 to_release = _cached_data_size - water_mark;
        u64 released_amount = 0;

        //
        // Mutex is a recursive lock - prevent the recursive locking since it's
        // exactly the case we are trying to avoid
        //
        if (!shrinker_lock.owned() && shrinker_lock.try_lock()) {

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

            shrinker_lock.unlock();

            _cached_data_size -= released_amount;
        }

        //printf("Released %ld bytes\n", released_amount);

        return released_amount;
    }

    void move_to_lru_front(cache_iterator& it, bool force = false)
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

    /**
     * The allocator will consume the appropriate power of 2 bytes per
     * allocation, so we need to take it into the account when estimating the
     * memory footprint.
     * @param val_bytes
     * @param key_bytes
     *
     * @return
     */
    u32 entry_mem_footprint(u32 val_bytes, u32 key_bytes)
    {
        u32 size = 0;

        // LRU entry
        size += (0x1UL << ilog2_roundup(sizeof(lru_entry)));
        size += (0x1UL << ilog2_roundup(sizeof(std::string) + key_bytes));

        // Cache entry
        size += (0x1UL << ilog2_roundup(sizeof(cache_type::value_type)));
        size += (0x1UL << ilog2_roundup(sizeof(std::string) + key_bytes));
        size += (0x1UL << ilog2_roundup(sizeof(std::string) + val_bytes));

        return size;
    }

private:
    const u16 _htons_1;
    u64 _cached_data_size;
    lockfree::mutex shrinker_lock;

    cache_type _cache;

    //
    // LRU keys list: the most rececently used at the front.
    //
    lru_type _cache_lru;

    //
    // Don't update the LRU location of the entry more than once per this period
    // of time in ns.
    //
    // Original memcached uses the same heuristics in order to reduce the noice
    // when a few entries are frequently accessed.
    //
    static const long long lru_update_interval = 60 * 1000000000LL; // 60 seconds
};

}

#endif /* MEMCACHED_UDP_HH_ */
