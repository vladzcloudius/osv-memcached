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
#include <cstdio>

using namespace std;

namespace osv_apps {

memcached::memcached() :
        _htons_1(ntohs(1)),
        _cached_data_size(0),
        _locked_shrinker(
            [this] (size_t n) { return this->shrink_cache_locked(n); })
{
    // Initialize commands hash (trie-based)
    cmd_hash["get"]       = GET;
    cmd_hash["delete"]    = DELETE;
    cmd_hash["set"]       = SET;
    cmd_hash["flush"]     = FLUSH;
    cmd_hash["decr"]      = DECR;
    cmd_hash["incr"]      = INCR;
    cmd_hash["add"]       = ADD;
    cmd_hash["get_stats"] = GET_STATS;
    cmd_hash["get_multi"] = GET_MULTI;
    cmd_hash["set_multi"] = SET_MULTI;
    cmd_hash["replace"]   = REPLACE;
    cmd_hash["cas"]       = CAS;
    cmd_hash["add_multi"] = ADD_MULTI;
}

inline u16 memcached::get_field_len(char* const start, const u16 max_len) const
{
    char *p = start, *pastend = start + max_len;

    while ((*p != ' ') && (*p != '\r') && (p < pastend)) {
        p++;
    }

    return p - start;
}

inline int memcached::do_get(char* packet, u16 len)
{
    //cerr<<"got 'get'\n";
    string str_key;
    if (!parse_key(packet + 4, len - 4, str_key)) {
        return send_cmd_error(packet);
    }

    char* reply = packet;
    char *r = reply + 6;

    WITH_LOCK(_locked_shrinker) {
        auto it = _cache.find(str_key);

        if (it == _cache.end()) {
            return send_cmd_end(packet);
        }

        // Check the expiration time. If entry has expired - delete it.
        unsigned long exptime = it->second.exptime;
        if (exptime && (exptime < get_secs_since_epoch())) {
            delete_cache_entry(it);
            return send_cmd_end(packet);
        }

        //cerr << "found\n";
        memcpy(reply, "VALUE ", 6);

        memcpy(r, str_key.data(), str_key.size());
        r += str_key.size();

        int data_len = it->second.data.size();
        r += std::sprintf(r, " %ld %d\r\n", it->second.flags, data_len);

        // Value
        memcpy(r, it->second.data.data(), data_len);
        r += data_len;

        memcpy(r, "\r\nEND\r\n", 7);
        r += 7;

        // Move the key to the front of the LRU
        move_to_lru_front(it->second);
    }

    return _hdr_len + (r - reply);
}

inline bool memcached::parse_key(char* p, u16 l, string& key)
{
    // Parse a "key"
    u16 flen = get_field_len(p, l);
    if (flen == l) {
        cerr<<"Bad packet format"<<endl;
        return false;
    }

    key.assign(p, flen);
    return true;
}

inline unsigned long memcached::get_secs_since_epoch() const
{
    auto wall_time = osv::clock::wall::now();
    auto dur = wall_time.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::seconds>(dur).count();
}

inline bool memcached::convert2epoch(unsigned long exptime,
                                     unsigned long& t) const
{
    t = exptime;

    //printf("exptime %ld\n", exptime);

    if (exptime == 0) {
        // never expire
        return true;
    } else if (exptime > max_expiration_since_now) {
        // It's a global time (since epoch)
        if (exptime < get_secs_since_epoch()) {
            return false;
        }

        return true;
    } else { // exptime <= max_expiration_since_now
        // It's a relative to "now" time
        t += get_secs_since_epoch();
        return true;
    }
}

/**
 * Try to parse a "noreply" option.
 *
 * "noreply" option is an optional option that always comes right before "\r\n"
 * sequence.
 *
 * @param p pointer to the symbol right after the last parsed token. The next
 *          symbol should be either '\r' or a beginning of a "nereply" token.
 *          The p will be updated to point to the next symbol after either
 *          "noreply" token (if present) or after "\r\n" sequence.
 * @param noreply true if there was a "noreply" token parsed and false
 *                otherwise. The value is undefined if the packet is malformed.
 *
 * @return false if a packet is malformed and true otherwise.
 */
inline bool memcached::parse_noreply(char*& p, bool& noreply) const
{
    if (*p != '\r') {
        if (strncmp(p + 1, "noreply", 7)) {
            cerr<<"Bad packet format: failed to parse \"noreply\" option"<<endl;
            return false;
        }

        noreply = true;
        p += 10;
        printf("Got noreply\n");
    } else {
        noreply = false;
        p += 2;
    }

    return true;
}

//
// Format of a command is as follows:
// <command name> <key> <flags> <exptime> <bytes> [noreply]\r\n
// <data>\r\n
//

/**
 * This function parsed the storage commands starting from the "flags" field
 * @param cmd
 * @param packet
 * @param len
 * @param cache_elem
 *
 * @return
 */
bool memcached::parse_storage_cmd(commands cmd, char* packet, u16 len,
                                  memcache_value& cache_elem, bool& noreply)
{
    unsigned long flags, exptime, bytes;
    char *p = packet, *end;

    // Parse flags
    flags = strtoul(p, &end, 10);
    if (errno) {
        cerr<<"Bad format in flags"<<endl;
        errno = 0;
        return false;
    }

    p = end;

    // Parse exptime
    exptime = strtoul(p, &end, 10);
    if (errno) {
        cerr<<"Bad format in exptime"<<endl;
        errno = 0;
        return false;
    }

    p = end;

    unsigned long aligned_exptime;
    if (!convert2epoch(exptime, aligned_exptime)) {
        cerr<<"Expiration time is in the past: "<<exptime<<endl;
        return false;
    }

    // Parse bytes number
    bytes = strtoul(p, &end, 10);
    if (errno) {
        cerr<<"Bad format in bytes (number)"<<endl;
        errno = 0;
        return false;
    }

    p = end;

    // Handle "noreply"
    if (!parse_noreply(p, noreply)) {
        return false;
    }

    if (len < (p - packet) + bytes + 2) {
        cerr << "got a too small packet ?! len="<<len
             <<", bytes="<<bytes<<"\n";
        return false;
    }

    // Update the cache entry
    cache_elem.exptime = aligned_exptime;
    cache_elem.flags = flags;

    switch (cmd) {
    case SET:
        cache_elem.data.assign(p, bytes);
        break;
    default:
        // Not supported command
        assert(0);
    }

    return true;
}

inline int memcached::do_set(char* packet, u16 len, bool& noreply)
{
    //cerr<<"got 'set'\n";
    char* p = packet + 4;
    u16 cur_len = len - 4;

    // Parse a "key"
    string str_key;
    if (!parse_key(p, cur_len, str_key)) {
        return send_cmd_error(packet);
    }

    p += str_key.size() + 1;
    cur_len -= str_key.size() + 1;
    size_t memory_needed;

    WITH_LOCK(_locked_shrinker) {
        memcache_value& cache_entry = _cache[str_key];

        if (!parse_storage_cmd(SET, p, cur_len, cache_entry, noreply)) {
            noreply = false;
            return send_cmd_error(packet);
        }

        memory_needed = entry_mem_footprint(cache_entry.data.size(),
                                            str_key.size());

        if (!cache_entry.initialized) {
            // Create a new LRU entry
            time_tracking_entry* entry = new time_tracking_entry(str_key);
            entry->mem_size = memory_needed;

            // Update the LRU list
            _cache_lru.push_front(*entry);
            cache_entry.lru_link = _cache_lru.begin();

            // Update the "expired" list and set links, set the expiration time
            cache_entry.exp_set_link  = _exp_set.end();
            entry->exptime = cache_entry.exptime;

            if (!cache_entry.exptime) {
                cache_entry.exp_list_link = _exp_list.end();
            } else {
                _exp_list.push_front(*entry);
                cache_entry.exp_list_link = _exp_list.begin();
            }

            cache_entry.initialized = true;

            #if 0
            if (bucket_count !=  _cache.bucket_count()) {
                bucket_count =  _cache.bucket_count();
                printf("bucket number is %d\n", bucket_count);
            }
            #endif
        } else {
             _cached_data_size -= cache_entry.lru_link->mem_size;
            cache_entry.lru_link->mem_size = memory_needed;

            // Move the key to the front of the LRU
            move_to_lru_front(cache_entry, true);
        }

        _cached_data_size += memory_needed;
    }


    //cerr<<"got set with " << bytes << " bytes\n";
    if (!noreply) {
        return send_cmd_stored(packet);
    } else {
        return 0;
    }
}


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
int memcached::process_request(char* packet, u16 len, bool& noreply)
{
    memcached_header* header = reinterpret_cast<memcached_header*>(packet);

    if ((len < _hdr_len) || memcached_header_invalid(header)) {
        // Cannot send reply, have no sequence number to reply to..
        cerr << "unknown packet format. len=" << len << "\n";
        return -1;
    }
    len -= _hdr_len;
    packet += _hdr_len;

    //
    // Command should not end at the packet end - there should be at least \r\n
    // following it.
    //
    u16 cmd_len = get_field_len(packet, len);

    if (cmd_len == len) {
        return send_cmd_error(packet);
    }

    //
    // Parse the command: we use a hash table for translation.
    // The "language" is too simple to justify a real parser.
    //
    auto cmd_it = cmd_hash.find(string(packet, cmd_len));
    if (cmd_it == cmd_hash.end()) {
        cerr<<"Got unknown command: "<<string(packet, cmd_len).c_str()<<endl;
        return send_cmd_error(packet);
    }
    return handle_command(cmd_it->second, packet, len, noreply);
}

inline int memcached::handle_command(commands cmd, char* p, u16 l,
                                     bool& noreply)
{
    switch (cmd) {
    case GET:
        return do_get(p, l);
    case SET:
        return do_set(p, l, noreply);
    default:
        cerr<<"Command "<<cmd<<" is not implemented yet"<<endl;
        return send_cmd_error(p);
    }
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

    // Check that the port is a memcached port
    if (ntohs(udp_hdr->uh_dport) != memcached_port_num) {
        return false;
    }

    bool noreply = false;

    int data_len = process_request(h + sizeof(udphdr),
                              ntohs(ip_hdr->ip_len) - ip_size - sizeof(udphdr),
                                   noreply);

    if (data_len < 0) {
        return false;
    }

    // If "noreply" received then we are done here
    if (noreply) {
        m_freem(m);
        return true;
    }
    // Set new mbuf len
    m->M_dat.MH.MH_pkthdr.len = m->m_hdr.mh_len =
        ip_size + sizeof(udphdr) + data_len;

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

size_t memcached::shrink_cache_locked(size_t n)
{
    size_t water_mark = (_cached_data_size / 10) * 9;
    size_t to_release = _cached_data_size - water_mark;
    size_t released_amount = 0;
    unsigned long secs_since_epoch = get_secs_since_epoch();

    to_release = MAX(to_release, n);
    to_release = MIN(to_release, _cached_data_size);

    //
    // First delete those that have expired.
    //
    // Start with moving the items from _exp_list to _exp_set
    //
    for (exp_list_iterator c = _exp_list.begin(); c != _exp_list.end();) {
        cache_iterator c_it = _cache.find(c->key);

        DEBUG_ASSERT(c_it != _cache.end(),
                     "Haven't found a cache entry for key [%s] "
                     "from the EXP list\n",
                     c->key.c_str());

        // If entry has already expired delete it
        if (c->exptime < secs_since_epoch) {
            released_amount += c->mem_size;
            ++c;
            delete_cache_entry(c_it);
        } else {
            exp_set_iterator s_it = _exp_set.insert(*c);
            exp_list_iterator old_c = c++;
            _exp_list.erase(old_c);

            c_it->second.exp_list_link = _exp_list.end();
            c_it->second.exp_set_link = s_it;
        }
    }

    // Then iterate over _exp_set and delete all expired entries
    for (exp_set_iterator c = _exp_set.begin();
         (c != _exp_set.end()) && (c->exptime < secs_since_epoch);) {
        cache_iterator c_it = _cache.find(c->key);

        DEBUG_ASSERT(c_it != _cache.end(),
                    "Haven't found a cache entry for key [%s] "
                    "from the EXP set\n",
                    c->key.c_str());

        released_amount += c->mem_size;
        ++c;
        delete_cache_entry(c_it);
    }

    lru_iterator it = _cache_lru.end();

    // Delete the rest of the entries starting from the least recently used ones
    for (--it; released_amount < to_release;) {
        cache_iterator c_it = _cache.find(it->key);

        DEBUG_ASSERT(c_it != _cache.end(),
                     "Haven't found a cache entry for key [%s] "
                     "from the LRU list\n",
                     it->key.c_str());

        released_amount += it->mem_size;
        --it;
        delete_cache_entry(c_it);
    }

    _cached_data_size -= released_amount;

    //printf("Released %ld bytes\n", released_amount);

    return released_amount;
}

inline void memcached::move_to_lru_front(memcache_value& cache_entry,
                                         bool force)
{
    auto link_ptr = &cache_entry.lru_link;
    auto entry_ptr = &(*(*link_ptr));

    using namespace std::chrono;

    //  Move the key to the front if it's not already there
    if (*link_ptr != _cache_lru.begin()) {
        auto now = oc::uptime::now();
        auto secs = duration_cast<seconds>(now -
                                           entry_ptr->last_touch_time).count();

        if (force || (secs > lru_update_interval)) {

            _cache_lru.erase(*link_ptr);
            _cache_lru.push_front(*entry_ptr);
            *link_ptr = _cache_lru.begin();
            entry_ptr->last_touch_time = now;
        }
    }
}

void inline memcached::delete_cache_entry(cache_iterator& it)
{
    if (it->second.exp_set_link != _exp_set.end()) {
        _exp_set.erase(it->second.exp_set_link);
    }

    if (it->second.exp_list_link != _exp_list.end()) {
        _exp_list.erase(it->second.exp_list_link);
    }

    _cache_lru.erase_and_dispose(it->second.lru_link, delete_disposer());
    _cache.erase(it);
}

} // namespace osv_apps

