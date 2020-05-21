//
//  blocker.cpp
//  blockerd
//
//  Created by Jozef on 19/05/2020.
//  Copyright © 2020 Jozef Zuzelka. All rights reserved.
//
// TODO: osetrit vynimky na future a std::any a casty a vsetko
// TODO: moze byt nebezpecne ked pridaju novy auth event vracajuci flagy a neosetrim to v default

#include <any>
#include <EndpointSecurity/EndpointSecurity.h>
#include <future>
#include <iostream>
#include <optional>
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
Blocker& Blocker::GetInstance()
{
    static Blocker blocker;
    return blocker;
}

#define ASYNCES 0
bool Blocker::Init()
{
    es_handler_block_t handler = ^(es_client_t *clt, const es_message_t *msg) {
#if ASYNCES
        es_message_t * const msgCopy = es_copy_message(msg);
        if (msgCopy == nullptr) {
            std::cerr << "Could not copy message." << std::endl;
            IncreaseStats(BlockerStats::EVENT_COPY_ERR);
            return;
        }

        dispatch_async(dispatch_get_main_queue(), ^(void){
#else  // ASYNCES
            es_message_t *msgCopy = (es_message_t*)msg;
#endif // ASYNCES
            uint64_t msecDeadline = mach_time_to_msecs(msgCopy->deadline);
            // Set deadline a bit sooner
            const std::chrono::milliseconds f_msecDeadline { msecDeadline - (msecDeadline >> 3) }; // substract 12.5%
//            std::cout << "Deadline: "
//                      << "Original <" << std::chrono::duration_cast<std::chrono::seconds>(std::chrono::milliseconds(msecDeadline)).count()
//                      << "> Set <" << std::chrono::duration_cast<std::chrono::seconds>(f_msecDeadline).count() << ">"
//                      << std::endl;
#define DO_STHES 1
#if DO_STHES
  #define WITH_DEADLINEES 1
  #if WITH_DEADLINEES
            // TODO: may throw an exception,
            std::future f = std::async(std::launch::async, [clt,msgCopy]{ Blocker::GetInstance().HandleEvent(clt, msgCopy); });

            const auto f_res = f.wait_until(std::chrono::steady_clock::now() + f_msecDeadline);
            if (msgCopy->action_type != ES_ACTION_TYPE_NOTIFY) {
                if (f_res == std::future_status::timeout) {
                    Blocker::GetInstance().IncreaseStats(BlockerStats::EVENT_DROPPED_DEADLINE, msg->event_type);
                    std::cerr << "Event dropped because of deadline!\n";
                }
                else if (f_res == std::future_status::timeout) {
                    std::cerr << "Event deffered (should not happen)!\n";
                }
            }
  #else   // WITH_DEADLINEES
            Blocker::GetInstance().HandleEvent(clt, msgCopy);
  #endif  // WITH_DEADLINEES
#else   // DO_STHES
            Stats::EventStats &eventStats = m_stats.eventStats[msg->event_type];
            // if it's the first event of its type don't check seq_num sequence
            if (eventStats.firstEvent == true) {
                eventStats.firstEvent = false;
            } // if we already had any event of its type and the sequence is broken we dropped an event
            else if ((eventStats.lastSeqNum + 1) != msg->seq_num) {
                std::cerr << "Event dropped!\n";
                IncreaseStats(BlockerStats::EVENT_DROPPED_KERNEL, msg->event_type, msg->seq_num - eventStats.lastSeqNum);
            } // else everything is ok

            // set the new lastSeq
            eventStats.lastSeqNum = msg->seq_num;

            if (msgCopy->action_type == ES_ACTION_TYPE_AUTH) {
                  if (msgCopy->action_type == ES_ACTION_TYPE_AUTH) {
                      // Handle subscribed AUTH events
                      es_respond_result_t res;

                      if (msgCopy->event_type == ES_EVENT_TYPE_AUTH_OPEN)
                          res = es_respond_flags_result(clt, msgCopy, msg->event.open.fflag, false);
                      else
                          res = es_respond_auth_result(clt, msgCopy, ES_AUTH_RESULT_ALLOW, false);

                      if (res != ES_RESPOND_RESULT_SUCCESS)
                          std::cerr << "es_respond_auth_result: " << g_respondResultToStrMap.at(res) << std::endl;
                  }
              }
              std::cerr << g_eventTypeToStrMap.at(msgCopy->event_type) << " Returning!\n";
  #if ASYNCES
              es_free_message(msgCopy);
  #endif
#endif  // DO_STHES
#if ASYNCES
        });
#endif // ASYNCES
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
    es_clear_cache_result_t resCache = es_clear_cache(m_clt);
    if (ES_CLEAR_CACHE_RESULT_SUCCESS != resCache) {
        std::cerr << "es_clear_cache: " << resCache << std::endl;
        return false;
    }

    // mute self
    // note: you might not want this, but for a cmdline-based filemonitor
    //       this ensures we don't constantly report writes to current /dev/tty
    es_mute_path_literal(m_clt, [NSProcessInfo.processInfo.arguments[0] UTF8String]);

    // Subscribe to the events we're interested in
    es_return_t subscribed = es_subscribe(m_clt, m_eventsOfInterest.data(), static_cast<uint32_t>(m_eventsOfInterest.size()));
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
    std::scoped_lock<std::mutex> lock(m_mtx);
    switch (metric)
    {
        case BlockerStats::EVENT_COPY_ERR:
            m_stats.eventStats[type].copyErr += count;
            break;
        case BlockerStats::EVENT_DROPPED_KERNEL:
            m_stats.eventStats[type].droppedKernel += count; // TODO: take into account ignored events
            break;
        case BlockerStats::EVENT_DROPPED_DEADLINE:
            m_stats.eventStats[type].droppedDeadline += count;
            break;
    }
}

std::optional<std::reference_wrapper<const CloudProvider>> Blocker::ResolveCloudProvider(const std::vector<const std::string> &paths)
{
    // TODO: recognize copy from one CloudProvider to another one
    for (const auto &[cpId,cp] : m_config) {
        static const auto findOccurence = [&cp = std::as_const(cp)](const std::string& eventPath) {
            for (const auto &cpPath : cp.paths) {
                if (eventPath.find(cpPath) != std::string::npos) {
                    std::cout << "*** Occurence found: " << eventPath << std::endl;
                    return true;
                }
            }
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
#if ASYNCES
    // AppleDoc: Warning: Freeing a message from inside a handler block will cause your app to crash.
    // But as this block is running async from the original block, freeing should be OK.
    es_free_message(msg);
#endif
}

std::any Blocker::HandleEventImpl(const es_message_t * const msg)
{
    std::any ret;
    std::string prefixToPrint;

    switch(msg->event_type) {
        // MARK: NOTIFY
        // TODO: design it better to make sure that this switch matches m_eventsOfInterest array
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
            const std::vector<const std::string> eventPaths = paths_from_file_event(msg);

            const auto cp = ResolveCloudProvider(eventPaths);
            // Not a supported cloud provider.
            if (!cp.has_value())
                break;

            // If no restriction is set
            if (cp->get().bl == BlockLevel::NONE || cp->get().BundleIdIsAllowed(msg->process->signing_id)) {
                prefixToPrint = "NOTIFY: ";
            }
            // TODO: we cannot do anything with notify event here
            else {
                prefixToPrint = "ERR: Cannot block ";
            }

            std::cout << prefixToPrint << g_eventTypeToStrMap.at(msg->event_type) << " operation at";
            for (const auto &path : eventPaths)
                std::cout << " '" << path << "'";
            std::cout << " by " << msg->process->signing_id << std::endl;
            std::cout << msg << std::endl;
            break;
        }
        // MARK: AUTH
        case ES_EVENT_TYPE_AUTH_OPEN:
        {
            ret = (uint32_t)msg->event.open.fflag;
            const std::vector<const std::string> eventPaths = paths_from_file_event(msg);
            
            const auto cp = ResolveCloudProvider(eventPaths);
            // Not a supported cloud provider.
            if (!cp.has_value())
                break;
            
            // If no restriction is set
            if (cp->get().bl == BlockLevel::NONE || cp->get().BundleIdIsAllowed(msg->process->signing_id)) {
                prefixToPrint = "Ignoring ";
            } else if (cp->get().bl == BlockLevel::RONLY) {
                ret = (uint32_t)FFLAGS(O_RDONLY);
                prefixToPrint = "BLOCKING (RONLY) ";
            } else if (cp->get().bl == BlockLevel::FULL) {
                ret = (uint32_t)0;
                prefixToPrint = "BLOCKING (FULL) ";
            }

            std::cout << prefixToPrint << g_eventTypeToStrMap.at(msg->event_type) << " operation at";
            for (const auto &path : eventPaths)
                std::cout << " '" << path << "'";
            std::cout << " by " << msg->process->signing_id << std::endl;
            std::cout << msg << std::endl;
            break;
        }
        case ES_EVENT_TYPE_AUTH_MOUNT:
        {
            ret = ES_AUTH_RESULT_ALLOW;
            std::cout << "ALLOWING OPERATION: " << g_eventTypeToStrMap.at(msg->event_type) << std::endl;
            std::cout << msg << std::endl;
            break;
        }
        case ES_EVENT_TYPE_AUTH_CREATE:
        case ES_EVENT_TYPE_AUTH_CLONE:
        case ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE:
        case ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE:
        case ES_EVENT_TYPE_AUTH_LINK:
        case ES_EVENT_TYPE_AUTH_READDIR:
        case ES_EVENT_TYPE_AUTH_READLINK:
        case ES_EVENT_TYPE_AUTH_RENAME:
        case ES_EVENT_TYPE_AUTH_TRUNCATE:
        case ES_EVENT_TYPE_AUTH_UNLINK:
        {
            ret = ES_AUTH_RESULT_ALLOW;
            const std::vector<const std::string> eventPaths = paths_from_file_event(msg);

            const auto cp = ResolveCloudProvider(eventPaths);
            // Not a supported cloud provider.
            if (!cp.has_value())
               break;

            std::string prefixToPrint;
            // If no restriction is set
            if (cp->get().bl == BlockLevel::NONE || cp->get().BundleIdIsAllowed(msg->process->signing_id)) {
               prefixToPrint = "Ignoring ";
            } else if (cp->get().bl == BlockLevel::RONLY) {
               // TODO: what to do with ronly !!!:
                ret = ES_AUTH_RESULT_DENY;
               prefixToPrint = "BLOCKING (RONLY) ";
            } else if (cp->get().bl == BlockLevel::FULL) {
                ret = ES_AUTH_RESULT_DENY;
               prefixToPrint = "BLOCKING (FULL) ";
            }

            std::cout << prefixToPrint << g_eventTypeToStrMap.at(msg->event_type) << " operation at";
            for (const auto &path : eventPaths)
               std::cout << " '" << path << "'";
            std::cout << " by " << msg->process->signing_id << std::endl;
            std::cout << msg << std::endl;
            break;
        }
        default: {
            if (msg->action_type == ES_ACTION_TYPE_AUTH)
                ret = ES_AUTH_RESULT_ALLOW;
            std::cout << "DEFAULT (should not happen!): " << g_eventTypeToStrMap.at(msg->event_type) << std::endl;
            std::cout << msg << std::endl;
            return ret; // to avoid indexing of dropped events vector with unsupported event...just in case - more for debug
        }
    }

    // TODO: thread safety
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

    return ret;
}

void Blocker::PrintStats()
{
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