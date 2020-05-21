//
//  blocker.cpp
//  blockerd
//
//  Created by Jozef on 19/05/2020.
//  Copyright © 2020 Jozef Zuzelka. All rights reserved.
//
// TODO: osetrit vynimky na future a std::any, casty a vlastne vsetky ostatne
// TODO: moze byt nebezpecne ked pridaju novy auth event vracajuci flagy a neosetri sa to v default
// TODO: skontrolovat thread safety

#include <any>
#include <EndpointSecurity/EndpointSecurity.h>
#include <future>
#include <iostream>
#include <sys/fcntl.h> // FREAD, FWRITE, FFLAGS
#import <Foundation/Foundation.h>

#include "../../Common/Tools/Tools.hpp"
#include "../../Common/Tools/Tools-ES.hpp"
#include "blocker.hpp"

// From <Kernel/sys/fcntl.h>
/* convert from open() flags to/from fflags; convert O_RD/WR to FREAD/FWRITE */
#define FFLAGS(oflags)  ((oflags) + 1)
#define OFLAGS(fflags)  ((fflags) - 1)

#define likely(x)      __builtin_expect(!!(x), 1) // [[likely]] for c++20
#define unlikely(x)    __builtin_expect(!!(x), 0) // [[unlikely]] for c++20


// MARK: - CloudProvider
bool CloudProvider::BundleIdIsAllowed(const es_string_token_t bundleId) const
{
    return (std::find(allowedBundleIds.begin(), allowedBundleIds.end(), to_string(bundleId)) != allowedBundleIds.end());
}


// MARK: - Blocker
static const inline std::map<BlockLevel, const std::string> g_blockLvlToStr = {
    {BlockLevel::NONE,  "NONE"},
    {BlockLevel::RONLY, "RONLY"},
    {BlockLevel::FULL,  "FULL"},
};


Blocker& Blocker::GetInstance()
{
    static Blocker blocker;
    return blocker;
}

#define BLOCKER_ASYNC_HANDLER 0
bool Blocker::Init()
{
    es_handler_block_t handler = ^(es_client_t *clt, const es_message_t *msg) {
#if BLOCKER_ASYNC_HANDLER
        es_message_t * const msgCopy = es_copy_message(msg);
        if (msgCopy == nullptr) {
            std::cerr << "Could not copy message." << std::endl;
            IncreaseStats(BlockerStats::EVENT_COPY_ERR);
            return;
        }

        dispatch_async(dispatch_get_main_queue(), ^(void){
#else  // BLOCKER_ASYNC_HANDLER
            es_message_t *msgCopy = (es_message_t*)msg;
#endif // BLOCKER_ASYNC_HANDLER
            uint64_t msecDeadline = mach_time_to_msecs(msgCopy->deadline);
            // Set deadline a bit sooner
            const std::chrono::milliseconds f_msecDeadline { msecDeadline - (msecDeadline >> 3) }; // substract 12.5%

            // TODO: may throw an exception,
            std::future f = std::async(std::launch::async, [clt,msgCopy]{ Blocker::GetInstance().HandleEvent(clt, msgCopy); });

            const auto f_res = f.wait_until(std::chrono::steady_clock::now() + f_msecDeadline);
            // The deadline is 0 for NOTIFY events
            if (msgCopy->action_type != ES_ACTION_TYPE_NOTIFY) {
                if (f_res == std::future_status::timeout) {
                    Blocker::GetInstance().IncreaseStats(BlockerStats::EVENT_DROPPED_DEADLINE, msg->event_type);
                    std::cerr << "Event dropped because of deadline!\n";
                }
                else if (f_res == std::future_status::timeout) {
                    std::cerr << "Event deffered (should not happen)!\n";
                }
            }
#if BLOCKER_ASYNC_HANDLER
        });
#endif // BLOCKER_ASYNC_HANDLER
    };

    es_new_client_result_t res = es_new_client(&m_clt, handler);

    // Handle any errors encountered while creating the client.
    if (res != ES_NEW_CLIENT_RESULT_SUCCESS) {
        if (res == ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED)
            std::cerr << "Application requires 'com.apple.developer.endpoint-security.client' entitlement\n";
        else if (res == ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED)
            std::cerr << "Application needs to run as root (and SIP disabled).\n";
        else if (res == ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED)
            // Prompt user to perform TCC approval.
            // This error is recoverable; the user can try again after
            // approving TCC.)
            std::cerr << "Application needs TCC approval.\n";
        else if (res == ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT)
            std::cerr << "Invalid argument to es_new_client(); client or handler was null.\n";
        else if (res == ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS)
            std::cerr << "Exceeded maximum number of simultaneously-connected ES clients.\n";
        else if (res == ES_NEW_CLIENT_RESULT_ERR_INTERNAL)
            std::cerr << "Failed to connect to the Endpoint Security subsystem.\n";
        else
            std::cerr << "es_new_client: " << res << std::endl;

        return false;
    }

    // Cache needs to be explicitly cleared between program invocations
    // TODO: validate this statement ^^
    es_clear_cache_result_t resCache = es_clear_cache(m_clt);
    if (ES_CLEAR_CACHE_RESULT_SUCCESS != resCache) {
        std::cerr << "es_clear_cache: " << resCache << std::endl;
        return false;
    }

    // Don't constantly report writes to current /dev/tty
    es_mute_path_literal(m_clt, [NSProcessInfo.processInfo.arguments[0] UTF8String]);

    // Subscribe to the events we're interested in
    es_return_t subscribed = es_subscribe(m_clt,
                                          m_eventsOfInterest.data(),
                                          static_cast<uint32_t>(m_eventsOfInterest.size()));
    if (subscribed == ES_RETURN_ERROR) {
        std::cerr << "es_subscribe: ES_RETURN_ERROR\n";
        return false;
    }

    return true;
}

void Blocker::Uninit()
{
    if(m_clt) {
        es_unsubscribe_all(m_clt);
        es_delete_client(m_clt);
        m_clt = nullptr;
    }
}

void Blocker::IncreaseStats(const BlockerStats metric, const es_event_type_t type, const uint64_t count )
{
    std::scoped_lock<std::mutex> lock(m_statsMtx);
    switch (metric)
    {
        case BlockerStats::EVENT_COPY_ERR:
            m_stats.eventStats[type].copyErr += count;
            break;
        case BlockerStats::EVENT_DROPPED_KERNEL:
            m_stats.eventStats[type].droppedKernel += count; // TODO: take ignored events into account
            break;
        case BlockerStats::EVENT_DROPPED_DEADLINE:
            m_stats.eventStats[type].droppedDeadline += count;
            break;
    }
}

std::optional<std::reference_wrapper<const CloudProvider>> Blocker::ResolveCloudProvider(const std::vector<const std::string> &paths)
{
    // TODO: recognize copy from one CloudProvider to another one
    // TODO: check thread safety of m_config and the returned CloudProvider
    for (const auto &[cpId,cp] : m_config) {
        static const auto findOccurence = [&cp = std::as_const(cp)](const std::string& eventPath) {
            for (const auto &cpPath : cp.paths)
                if (eventPath.find(cpPath) != std::string::npos)
                    return true;

            return false;
        };

        // found if the path belongs to any cloud
        if (std::any_of(paths.cbegin(), paths.cend(), findOccurence)) {
            return cp;
        }
    }
    return std::nullopt;
}

// MARK: Callbacks
void Blocker::HandleEvent(es_client_t * const clt, es_message_t * const msg)
{
    std::any ret = HandleEventImpl(msg);
    // If it's an AUTH event, we need to return something
    if (msg->action_type == ES_ACTION_TYPE_AUTH) {
        if (!ret.has_value()) {
            std::cerr << "HandleEventImpl did not return a value!!\n";
            return;
        }

        // Handle subscribed AUTH events
        es_respond_result_t res;
        if (msg->event_type == ES_EVENT_TYPE_AUTH_OPEN) {
            res = es_respond_flags_result(clt, msg, std::any_cast<uint32_t>(ret), false);
        } else {
            res = es_respond_auth_result(clt, msg, std::any_cast<es_auth_result_t>(ret), false);
        }

        if (res != ES_RESPOND_RESULT_SUCCESS)
            std::cerr << "es_respond_auth_result: " << g_respondResultToStrMap.at(res) << std::endl;
    }
#if BLOCKER_ASYNC_HANDLER
    // AppleDoc: Warning: Freeing a message from inside a handler block will cause your app to crash.
    // But as this block is running asynchronously from the original block, freeing should be OK here.
    es_free_message(msg);
#endif
}

std::any Blocker::HandleEventImpl(const es_message_t * const msg)
{
    // std::cout << "OPERATION IMPL: " << g_eventTypeToStrMap.at(msg->event_type) << std::endl;
    // Dirty temporary hack.
    // Set default non-destructive return. AUTH_OPEN returns flags, other auth events return AUTH_RESULT and notify does not care.
    std::any ret;
    if (msg->event_type == ES_EVENT_TYPE_AUTH_OPEN)
        ret = static_cast<uint32_t>(msg->event.open.fflag);
    else
        ret = static_cast<es_auth_result_t>(ES_AUTH_RESULT_ALLOW);

    try {
        // At first get some metrics
        // std::scoped_lock<std::mutex> lock(m_statsMtx); // !!!: causes deadlock. Fix thread safety!
        Stats::EventStats &eventStats = m_stats.eventStats[msg->event_type];
        // if it's the first event of its type don't check seq_num sequence
        if (unlikely(eventStats.firstEvent == true)) {
            eventStats.firstEvent = false;
        } // if we already had any event of its type and the sequence is broken we dropped an event
        else if (unlikely((eventStats.lastSeqNum + 1) != msg->seq_num)) {
            std::cerr << "Event dropped!\n";
            IncreaseStats(BlockerStats::EVENT_DROPPED_KERNEL, msg->event_type, msg->seq_num - eventStats.lastSeqNum);
        } // else everything is ok

        // set the new lastSeq
        eventStats.lastSeqNum = msg->seq_num;

        // !!!: This call WILL crash with unsupported event type
        const std::vector<const std::string> eventPaths = paths_from_event(msg);

        const auto cp = ResolveCloudProvider(eventPaths);
        // Not a supported cloud provider.
        if (!cp.has_value())
            return ret;

        switch(msg->event_type) {
            // MARK: NOTIFY
            // TODO: make a better design to make sure that this switch matches m_eventsOfInterest array
            case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
            case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD:
            case ES_EVENT_TYPE_NOTIFY_UNMOUNT:
            {
                std::cout << "NOTIFY OPERATION: " << g_eventTypeToStrMap.at(msg->event_type) << std::endl;
                std::cout << msg << std::endl;
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_ACCESS:
            case ES_EVENT_TYPE_NOTIFY_CLOSE:
            case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
            case ES_EVENT_TYPE_NOTIFY_WRITE:
            {
                std::string prefixToPrint;
                // If no restriction is set
                if (cp->get().bl == BlockLevel::NONE || cp->get().BundleIdIsAllowed(msg->process->signing_id)) {
                    prefixToPrint = "NOTIFY: ";
                }
                else {
                    // TODO: we cannot do anything with notify event here. Deal with it (mainly with WRITE which was invoked by `ls`)
                    prefixToPrint = "ERR: Cannot block ";
                }

                std::cout << std::endl << prefixToPrint << std::endl
                          << (std::any_cast<es_auth_result_t>(ret) == ES_AUTH_RESULT_DENY ? " BLOCKING " : " ALLOWING ")
                          << "(" << g_blockLvlToStr.at(cp->get().bl) << ") "
                          << g_eventTypeToStrMap.at(msg->event_type) << " operation at" << std::flush;
                for (const auto &path : eventPaths)
                    std::cout << " '" << path << "'";
                std::cout << " by " << msg->process->signing_id << std::endl;
                std::cout << msg << std::endl;
                break;
            }
            // MARK: AUTH
            case ES_EVENT_TYPE_AUTH_OPEN:
            {
                char *allowedFlags = nullptr;
                char *blockedFlags = nullptr;
                char *flags = esfflagstostr(std::any_cast<uint32_t>(ret));

                // If any restriction is set
                if (cp->get().bl != BlockLevel::NONE && !cp->get().BundleIdIsAllowed(msg->process->signing_id)) {
                    uint32_t mask = ~0; // Do not change the flags...if anything goes wrong

                    if (cp->get().bl == BlockLevel::RONLY) {
                        mask = ~(FWRITE | FAPPEND | O_CREAT); // TODO: validate these flags
                    } else {
                        mask = 0;
                    }
                    ret = (uint32_t)(msg->event.open.fflag & mask);
                }
                allowedFlags = esfflagstostr(std::any_cast<uint32_t>(ret));
                blockedFlags = esfflagstostr(std::any_cast<uint32_t>(ret) ^ msg->event.open.fflag);

                std::cout << std::endl
                          << "(" << g_blockLvlToStr.at(cp->get().bl) << ") "
                          << "ALLOWING (" << allowedFlags << "), BLOCKING (" << blockedFlags << ") "
                          << g_eventTypeToStrMap.at(msg->event_type) << " operation at";
                for (const auto &path : eventPaths)
                    std::cout << " '" << path << "'";
                std::cout << " by " << msg->process->signing_id << std::endl;

                free(flags);        flags = nullptr;
                free(allowedFlags); allowedFlags = nullptr;
                free(blockedFlags); blockedFlags = nullptr;
                break;
            }
            case ES_EVENT_TYPE_AUTH_MOUNT:
            {
                std::cout << std::endl << "ALLOWING OPERATION: " << g_eventTypeToStrMap.at(msg->event_type) << std::endl;
                std::cout << msg << std::endl;
                break;
            }
            case ES_EVENT_TYPE_AUTH_READDIR:
            {
                // DENY only in FULL blocking mode
                if (cp->get().bl == BlockLevel::FULL && !cp->get().BundleIdIsAllowed(msg->process->signing_id)) {
                    ret = static_cast<es_auth_result_t>(ES_AUTH_RESULT_DENY);
                }

                std::cout << std::endl
                          << "(" << g_blockLvlToStr.at(cp->get().bl) << ") "
                          << (std::any_cast<es_auth_result_t>(ret) == ES_AUTH_RESULT_DENY ? "BLOCKING " : "ALLOWING ")
                          << g_eventTypeToStrMap.at(msg->event_type) << " operation at";
                for (const auto &path : eventPaths)
                    std::cout << " '" << path << "'";
                std::cout << " by " << msg->process->signing_id << std::endl;
                break;
            }
            case ES_EVENT_TYPE_AUTH_CREATE: // TODO: check when it's called for proper blocking
            case ES_EVENT_TYPE_AUTH_CLONE: // TODO: check when it's called for proper blocking
            case ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE: // TODO: check when it's called for proper blocking
            case ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE: // TODO: check when it's called for proper blocking
            case ES_EVENT_TYPE_AUTH_LINK: // TODO: check when it's called for proper blocking
            case ES_EVENT_TYPE_AUTH_READLINK:
            case ES_EVENT_TYPE_AUTH_RENAME: // TODO: check when it's called for proper blocking
            case ES_EVENT_TYPE_AUTH_TRUNCATE: // TODO: check when it's called for proper blocking
            case ES_EVENT_TYPE_AUTH_UNLINK: // TODO: check when it's called for proper blocking
            {
                // Also RONLY mode, these events are content-changing operations so we don't have to check the mode.
                // Just deny the operation...
                if (cp->get().bl != BlockLevel::NONE && !cp->get().BundleIdIsAllowed(msg->process->signing_id)) {
                    ret = (es_auth_result_t)ES_AUTH_RESULT_DENY;
                }

                std::cout << std::endl
                          << "(" << g_blockLvlToStr.at(cp->get().bl) << ") "
                          << (std::any_cast<es_auth_result_t>(ret) == ES_AUTH_RESULT_DENY ? "BLOCKING " : "ALLOWING ")
                          << g_eventTypeToStrMap.at(msg->event_type) << " operation at";
                for (const auto &path : eventPaths)
                    std::cout << " '" << path << "'";
                std::cout << " by " << msg->process->signing_id << std::endl;
                break;
            }
            default: {
                if (msg->action_type == ES_ACTION_TYPE_AUTH)
                    ret = (es_auth_result_t)ES_AUTH_RESULT_ALLOW;
                std::cout << std::endl << "DEFAULT (should not happen!): " << g_eventTypeToStrMap.at(msg->event_type) << std::endl;
                std::cout << msg << std::endl;
                return ret; // to avoid indexing of dropped events vector with unsupported event...just in case - more for debug
            }
        }
    }
    catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "Unknown exception!" << std::endl;
    }
    return ret;
}

void Blocker::PrintStats()
{
    std::scoped_lock<std::mutex> lock(m_statsMtx);
    std::cout << m_stats << std::endl;
}

std::ostream & operator << (std::ostream &out, const Blocker::Stats &stats)
{
    uint64_t copyErrorsSum = 0;
    uint64_t kernelDropsSum = 0;
    uint64_t deadlineDropsSum = 0;

    out << "--- BLOCKER STATS ---";
    for (const auto &[eventType,eventStats] : stats.eventStats) {
        out << std::endl << "Event: " << g_eventTypeToStrMap.at(eventType);
        copyErrorsSum += eventStats.copyErr;
        out << std::endl << "Copy Errors: " << eventStats.copyErr;
        kernelDropsSum += eventStats.droppedKernel;
        out << std::endl << "Kernel Drops: " << eventStats.droppedKernel;
        deadlineDropsSum += eventStats.droppedDeadline;
        out << std::endl << "Deadline Drops: " << eventStats.droppedDeadline;
    }

    out << std::endl << " -- Summary:";
    out << std::endl << "Copy Errors: " << copyErrorsSum;
    out << std::endl << "Kernel Drops: " << kernelDropsSum;
    out << std::endl << "Deadline Drops: " << deadlineDropsSum;
    return out;
}
