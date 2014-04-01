#ifndef _LOCKED_SHRINKER_HH
#define _LOCKED_SHRINKER_HH

#include <sys/cdefs.h>
#include <sys/types.h>
#include <osv/types.h>
#include <osv/mempool.hh>

#include <functional>

namespace osv_apps {
/**
 * @class locked_shrinker
 *
 * This class is meant to protect the memory consumption and memory shrinking
 * critical sections.
 *
 * It implements the memory::shrinker interface to get triggers for memory
 * freeing.
 *
 * It implements lock()/unlock() methods to have a semanticist of standard mutex
 * and to work with WITH_LOCK() macros.
 *
 * It prevents the dead-lock situation in the shrinking flow (when shrinking is
 * caused by the allocation of a new memory for the cache) by using a try_lock()
 * in the shrinking flow. If there is a lock contention during the shrinking
 * then it sets the shrinking to the next time the lock() method is called.
 */
class locked_shrinker : public memory::shrinker {
public:
    locked_shrinker(std::function<u64 (size_t)> func) :
        memory::shrinker("osv-memcached-locked-shrinker"),
        _shrink_cache_locked_func(func) {}

    /**
     * Take a lock and call a shrinking if it's pending.
     */
    void lock()
    {
        _lock.lock();
        if (_bytes_to_release) {
            _shrink_cache_locked_func(_bytes_to_release);
            _bytes_to_release = 0;
        }
    }

    void unlock() { _lock.unlock(); }

    size_t request_memory(size_t n)
    {
        //
        // Don't block here to prevent a dead-lock:
        //
        // allocation in a critical section may trigger a shrinker and will
        // block until it ends - deadlock.
        //
        if (_lock.try_lock()) {

            u64 released_amount = _shrink_cache_locked_func(n);
            _bytes_to_release = 0;

            _lock.unlock();

            return released_amount;
        } else {
            _bytes_to_release = n;

            return 0;
        }
    }

    size_t release_memory(size_t n)
    {
        return 0;
    }

private:
    lockfree::mutex _lock;
    std::function<u64 (size_t)> _shrink_cache_locked_func;
    size_t _bytes_to_release = 0;
};

} // namespace osv_apps

#endif //_LOCKED_SHRINKER_HH
