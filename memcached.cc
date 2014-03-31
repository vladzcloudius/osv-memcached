#include <features.h>
#include <string>
#include <osv/types.h>
#include <memcached-udp.hh>
#include <bsd/sys/net/pfil.h>

using namespace std;

static inline void usage()
{
    cout<<endl<<endl<<" Usage: osv-memcached"<<endl<<endl;
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
    #if 0
    int i;

    // Parse args
    for (i = 1; i < argc; i++) {
        cerr<<"Unknown parameter: "<<argv[i]<<endl;
        usage();
        return 1;
    }
    #endif

    osv_apps::memcached memcached;

    // Add a PF filter for the memcached
    pfil_add_hook(memcached_pf_hook, (void*)&memcached, PFIL_IN | PFIL_WAITOK,
                  &V_inet_pfil_hook);

    cout<<"Press 'e' + 'ENTER' to exit"<<endl;
    char ch;
    while (1) {
        cin>>ch;
        if (ch == 'e') {
            break;
        } else {
            cout<<"Got: "<<ch<<endl;
        }
    }

    return 0;
}
