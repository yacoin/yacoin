// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2024 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YACOIN_SCHEDULER_H
#define YACOIN_SCHEDULER_H

//
// NOTE:
// boost::thread / boost::chrono should be ported to std::thread / std::chrono
// when we support C++11.
//
#include <boost/chrono/chrono.hpp>
#include <boost/thread.hpp>
#include <map>

#include "sync.h"

//
// Simple class for background tasks that should be run
// periodically or once "after a while"
//
// Usage:
//
// CScheduler* s = new CScheduler();
// s->scheduleFromNow(doSomething, 11); // Assuming a: void doSomething() { }
// s->scheduleFromNow(std::bind(Class::func, this, argument), 3);
// boost::thread* t = new boost::thread(boost::bind(CScheduler::serviceQueue, s));
//
// ... then at program shutdown, clean up the thread running serviceQueue:
// t->interrupt();
// t->join();
// delete t;
// delete s; // Must be done after thread is interrupted/joined.
//

class CScheduler
{
public:
    CScheduler();
    ~CScheduler();

    typedef std::function<void(void)> Function;

    // Call func at/after time t
    void schedule(Function f, boost::chrono::system_clock::time_point t=boost::chrono::system_clock::now());

    // Convenience method: call f once deltaSeconds from now
    void scheduleFromNow(Function f, int64_t deltaMilliSeconds);

    // Another convenience method: call f approximately
    // every deltaSeconds forever, starting deltaSeconds from now.
    // To be more precise: every time f is finished, it
    // is rescheduled to run deltaSeconds later. If you
    // need more accurate scheduling, don't use this method.
    void scheduleEvery(Function f, int64_t deltaMilliSeconds);

    // To keep things as simple as possible, there is no unschedule.

    // Services the queue 'forever'. Should be run in a thread,
    // and interrupted using boost::interrupt_thread
    void serviceQueue();

    // Tell any threads running serviceQueue to stop as soon as they're
    // done servicing whatever task they're currently servicing (drain=false)
    // or when there is no work left to be done (drain=true)
    void stop(bool drain=false);

    // Returns number of tasks waiting to be serviced,
    // and first and last task times
    size_t getQueueInfo(boost::chrono::system_clock::time_point &first,
                        boost::chrono::system_clock::time_point &last) const;

    // Returns true if there are threads actively running in serviceQueue()
    bool AreThreadsServicingQueue() const;

private:
    std::multimap<boost::chrono::system_clock::time_point, Function> taskQueue;
    boost::condition_variable newTaskScheduled;
    mutable boost::mutex newTaskMutex;
    int nThreadsServicingQueue;
    bool stopRequested;
    bool stopWhenEmpty;
    bool shouldStop() { return stopRequested || (stopWhenEmpty && taskQueue.empty()); }
};

/**
 * Class used by CScheduler clients which may schedule multiple jobs
 * which are required to be run serially. Does not require such jobs
 * to be executed on the same thread, but no two jobs will be executed
 * at the same time.
 */
class SingleThreadedSchedulerClient {
private:
    CScheduler *m_pscheduler;

    CCriticalSection m_cs_callbacks_pending;
    std::list<std::function<void (void)>> m_callbacks_pending;
    bool m_are_callbacks_running = false;

    void MaybeScheduleProcessQueue();
    void ProcessQueue();

public:
    SingleThreadedSchedulerClient(CScheduler *pschedulerIn) : m_pscheduler(pschedulerIn) {}
    void AddToProcessQueue(std::function<void (void)> func);

    // Processes all remaining queue members on the calling thread, blocking until queue is empty
    // Must be called after the CScheduler has no remaining processing threads!
    void EmptyQueue();
};

#endif
