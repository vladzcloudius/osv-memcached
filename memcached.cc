#include <features.h>
#include <string>
#include <osv/types.h>
#include <memcached-udp.hh>
#include <bsd/sys/net/pfil.h>

using namespace std;

static constexpr u64 default_max_cache_size = 64 * 1024 * 1024; // 64MB

static inline void usage()
{
    cout<<endl<<endl<<" Usage: osv-memcached [-m <num>]"<<endl<<endl;
    cout<<"    -m <num> - Use max <num> MB memory to use for object storage; "
                         "the default is 64 megabytes."<<endl;
    cout<<endl;
}

static inline int memcached_pf_hook(
    void *argv, struct mbuf **m, struct ifnet *ifn, int dir, struct inpcb *inp)
{
    osv_apps::memcached* memcached = static_cast<osv_apps::memcached*>(argv);

    //printf("Called hook for mbuf %p dir %d\n", *m, dir);
    bool res = memcached->filter(ifn, *m);
    return (!res) ? 0 : 1;
}

int main(int argc, char* argv[])
{
    int i;
    u64 max_cache_size = default_max_cache_size;

    // Parse args
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-m")) {
            i++;
            long tmp = stol(argv[i]);
            if (tmp < 0) {
                cerr<<"Bad format for the cache size: "<<argv[i]<<endl;
                usage();
                return 1;
            }

            max_cache_size = static_cast<u64>(tmp) * 1024 * 1024;
            cout<<"osv-memcached: MAX data cache size is "<<max_cache_size<<endl;
        } else {
            cerr<<"Unknow parameter: "<<argv[i]<<endl;
            usage();
            return 1;
        }
    }

    osv_apps::memcached memcached(max_cache_size);

    // Add a PF filter for the memcached
    pfil_add_hook(memcached_pf_hook, (void*)&memcached, PFIL_IN | PFIL_WAITOK,
                  &V_inet_pfil_hook);

    cout<<"Press 'e' + 'ENTER' to exit"<<endl;
    char ch;
    while (1) {
        cin >> ch;
        if (ch == 'e') {
            break;
        } else {
            cout<<"Got: "<<ch<<endl;
        }
    }

    return 0;
}
