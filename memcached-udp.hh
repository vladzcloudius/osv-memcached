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
#include <boost/intrusive/set.hpp>

#include <locked_shrinker.hh>

namespace bi = boost::intrusive;
namespace oc = osv::clock;
namespace osv_apps {

class memcached {
public:
    //
    // Note: protocol specifies the key as limited to 250 bytes, no spaces or
    // control chars.
    //
    typedef std::string memcache_key;

    //////////////// EXPIRED and LRU //////////
    struct time_tracking_entry {
        // seconds since epoch  
        unsigned long            exptime;
        memcache_key             key;
        // Time point when the entry has been updated/moved for the last time
        oc::uptime::time_point   last_touch_time;
        size_t                   mem_size;

        time_tracking_entry(const std::string& k) :
            key(k), last_touch_time(oc::uptime::now()), mem_size(0) {}

        // hook for a heap by "expired" field
        bi::set_member_hook<>    exp_set_hook;

        //
        // hook for a list of new entries that hasn't been added to the heap by
        // "expired" field. They will be moved from this list to the heap during
        // the "shrinking".
        //
        bi::list_member_hook<>   exp_list_hook;

        // hook for an LRU list
        bi::list_member_hook<>   lru_list_hook;

        friend bool operator<(const time_tracking_entry& a,
                              const time_tracking_entry& b)
        {
            return a.exptime < b.exptime;
        }

        friend bool operator==(const time_tracking_entry& a,
                              const time_tracking_entry& b)
        {
            return a.exptime == b.exptime;
        }

        friend bool operator>(const time_tracking_entry& a,
                              const time_tracking_entry& b)
        {
            return a.exptime > b.exptime;
        }
    };

    typedef bi::member_hook<time_tracking_entry,
                            bi::set_member_hook<>,
                            &time_tracking_entry::exp_set_hook>
                                                        exp_set_member_option;
	typedef bi::member_hook<time_tracking_entry,
                            bi::list_member_hook<>,
                            &time_tracking_entry::exp_list_hook>
                                                        exp_list_member_option;
    typedef bi::member_hook<time_tracking_entry,
                            bi::list_member_hook<>,
                            &time_tracking_entry::lru_list_hook>
                                                        lru_list_member_option;

    typedef bi::multiset<time_tracking_entry, exp_set_member_option> exp_set_type;
    typedef bi::list<time_tracking_entry, exp_list_member_option>    exp_list_type;
    typedef bi::list<time_tracking_entry, lru_list_member_option>    lru_type;

    typedef exp_set_type::iterator                            exp_set_iterator;
    typedef exp_list_type::iterator                           exp_list_iterator;
    typedef lru_type::iterator                                lru_iterator;

    //////////////// CACHE ////////////
    struct memcache_value {
        memcache_value() : initialized(false) {}

        lru_iterator  lru_link;
        exp_set_iterator exp_set_link;
        exp_list_iterator exp_list_link;
        std::string   data;
        //
        // "flags" is an opaque 32-bit integer which the clients gives in the
        // "set" command, and is echoed back on "get" commands.
        //
        u32           flags;
        unsigned long exptime;

        bool          initialized;
    };

    typedef std::unordered_map<memcache_key, memcache_value> cache_type;
    typedef cache_type::iterator                             cache_iterator;


    explicit memcached();

    bool filter(struct ifnet* ifn, mbuf* m);

private:
    enum commands {
        GET,
        DELETE,
        SET,
        FLUSH,
        DECR,
        INCR,
        ADD,
        GET_STATS,
        GET_MULTI,
        SET_MULTI,
        REPLACE,
        CAS,
        ADD_MULTI,
        COMMANDS_CNT
    };

    // The first 8 bytes of each UDP memcached request is the following header,
    // composed of four 16-bit integers in network byte order:
    struct memcached_header {
        // request_id is an opaque value that the server needs to echo back
        // to the client.
        u16 request_id;
        //
        // If the request or response spans n datagrams, number_of_datagrams
        // contains n, and sequence_number goes from 0 to n-1.
        //
        // Memcached does not currently support multi-datagram requests, so
        // neither do we have to. Memcached does support multi-datagram
        // responses, but the documentation suggest that TCP is more suitable
        // for this use case anyway, so we don't support this case as well.
        //
        // This means we can always reuse a request header as the response
        // header!
        //
        u16 sequence_number_n;
        u16 number_of_datagrams_n;
        // Reserved for future use, should be 0
        u16 reserved;
    };

    //The disposer object function
    struct delete_disposer
    {
        void operator()(time_tracking_entry* delete_this)
        {
            delete delete_this;
        }
    };

    /**
     * Parse and handle memcache request.
     * @param packet Pointer to the memcache data
     * @param len    Size of the memcache data
     */
    int process_request(char* packet, u16 len, bool& noreply);

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

        return _hdr_len + sizeof(msg) - 1;
    }

    int send_cmd_stored(char* packet) {
        constexpr static char msg[] = "STORED\r\n";

        memcpy(packet, msg, sizeof(msg) - 1);

        return _hdr_len + sizeof(msg) - 1;
    }

    int send_cmd_end(char* packet) {
        constexpr static char msg[] = "END\r\n";

        memcpy(packet, msg, sizeof(msg) - 1);

        return _hdr_len + sizeof(msg) - 1;
    }

    int send_cmd_ok(char* packet) {
        constexpr static char msg[] = "OK\r\n";

        memcpy(packet, msg, sizeof(msg) - 1);

        return _hdr_len + sizeof(msg) - 1;
    }

    int send_cmd_deleted(char* packet) {
        constexpr static char msg[] = "DELETED\r\n";

        memcpy(packet, msg, sizeof(msg) - 1);

        return _hdr_len + sizeof(msg) - 1;
    }

    int send_cmd_not_found(char* packet) {
        constexpr static char msg[] = "NOT_FOUND\r\n";

        memcpy(packet, msg, sizeof(msg) - 1);

        return _hdr_len + sizeof(msg) - 1;
    }

    /**
     * Currently memcache protocol doesn't support multi-frame requests - only
     * responces.
     * @param hdr
     *
     * @return
     */
    bool memcached_header_invalid(memcached_header* hdr)
    {
        return (hdr->sequence_number_n != 0) ||
               (ntohs(hdr->number_of_datagrams_n) > 1);
        // Could have also checked reserved !=0, but memaslap actually sets
        // it to 1...
    }

    /**
     * Shrink the cache by 10% of the current size.
     */
    size_t shrink_cache_locked(size_t n);

    void move_to_lru_front(memcache_value& cache_entry, bool force = false);

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
     * Calculate the approximate bytes number needed for cache entry
     *
     * @note The allocator will consume the appropriate power of 2 bytes per
     * allocation, so we need to take it into the account when estimating the
     * memory footprint.
     * @param val_bytes
     * @param key_bytes
     *
     * @return the estimate of bytes number that will be consumed for this new
     *         cache entry
     */
    size_t entry_mem_footprint(u32 val_bytes, u32 key_bytes)
    {
        size_t size = 0;

        // LRU entry
        size += (0x1UL << ilog2_roundup(sizeof(time_tracking_entry)));
        size += (0x1UL << ilog2_roundup(sizeof(std::string) + key_bytes));

        // Cache entry
        size += (0x1UL << ilog2_roundup(sizeof(cache_type::value_type)));
        size += (0x1UL << ilog2_roundup(sizeof(std::string) + key_bytes));
        size += (0x1UL << ilog2_roundup(sizeof(std::string) + val_bytes));

        return size;
    }

    /**
     * Find the end of the current field limited by either a space or '\r'
     * @param start first character of the current field
     * @param max_len Maximum field length
     *
     * @return the length of the current field not including the space or
     *         end-of-line charachter at the end.
     */
    u16 get_field_len(char* const start, const u16 max_len) const;

    // Command handlers
    int do_get(char* packet, u16 len);
    int do_set(char* packet, u16 len, bool& noreply);
    int do_flush_all(char* p, u16 l, bool& noreply);
    int do_delete(char* p, u16 l, bool& noreply);

    int handle_command(commands cmd, char* packet, u16 len, bool& noreply);
    bool parse_storage_cmd(commands cmd, char* packet, u16 len,
                           memcache_value* cache_elem, bool& noreply);
    bool parse_key(char*& p, u16& l, std::string& key);
    bool parse_noreply(char*& p, u16& l, bool& noreply) const;
    void eat_spaces(char*& p, u16& l) const;

    bool convert2epoch(unsigned long exptime, unsigned long& t) const;
    unsigned long get_secs_since_epoch() const;
    void delete_cache_entry(cache_iterator& it);
    void set_new_cache_entry(memcache_value& cache_entry,
                             const std::string& str_key,
                             const size_t& memory_needed);
    void delete_all_cache_entries();

private:
    const size_t _hdr_len = sizeof(memcached_header);
    size_t _cached_data_size;
    locked_shrinker _locked_shrinker;
    cache_type _cache;

    //
    // LRU keys list: the most rececently used at the front.
    //
    lru_type      _cache_lru;

    //
    // heap and list for handling the expiration field.
    // - When a new cache value is created and it has an expiration time then
    //   it's added to the _exp_list to make it quick.
    // - Then when a "shrinker" callback is called all non-expired entries are
    //   moved from the _exp_list to _exp_set to enable quick evicting.
    //
    exp_set_type  _exp_set;
    exp_list_type _exp_list;

    std::unordered_map<std::string, commands> cmd_hash;

    //
    // Don't update the LRU location of the entry more than once per this period
    // of time in ns.
    //
    // Original memcached uses the same heuristics in order to reduce the noice
    // when a few entries are frequently accessed.
    //
    static const int lru_update_interval = 60; // 60 seconds
    static const u16 memcached_port_num  = 11211;

    //
    // if "exptime" is less or equal this value (30 days) than it's a number of
    // seconds since "now", otherwise it's number of seconds since the "Unix
    // epoch" (midnight, Jan 1st, 1970).
    //
    static const unsigned long max_expiration_since_now = 60UL*60*24*30;
};

}

#endif /* MEMCACHED_UDP_HH_ */
