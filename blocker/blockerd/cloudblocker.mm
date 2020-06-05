//
//  cloudblocker.cpp
//  blockerd
//
//  Created by Jozef on 05/06/2020.
//  Copyright © 2020 Jozef Zuzelka. All rights reserved.
//

#include <any>
#include <EndpointSecurity/EndpointSecurity.h>
#include <future>
#include <iostream>
#include <paths.h>      // _PATH_CONSOLE
#include <pwd.h>        // getpwuid()
#include <sys/fcntl.h>  // FREAD, FWRITE
#import <Foundation/Foundation.h>

#include "../../Common/logger.hpp"
#include "../../Common/Tools/Tools.hpp"
#include "../../Common/Tools/Tools-ES.hpp"
#include "Clouds/base.hpp"
#include "Clouds/dropbox.hpp"
#include "Clouds/icloud.hpp"
#include "cloudblocker.hpp"

// From <Kernel/sys/fcntl.h>
/* convert from open() flags to/from fflags; convert O_RD/WR to FREAD/FWRITE */
#define FFLAGS(oflags)  ((oflags) + 1)
#define OFLAGS(fflags)  ((fflags) - 1)

#define likely(x)      __builtin_expect(!!(x), 1) // [[likely]] for c++20
#define unlikely(x)    __builtin_expect(!!(x), 0) // [[unlikely]] for c++20

static Logger &g_logger = Logger::getInstance();

// MARK: - Public
bool CloudBlocker::Init()
{
    es_handler_block_t handler = ^(es_client_t *clt, const es_message_t *msg) {
        es_message_t *msgCopy = es_copy_message(msg);
        if (msgCopy == nullptr) {
            g_logger.log(LogLevel::ERR, DEBUG_ARGS, "Could not copy message.");
            IncreaseStats(CloudBlockerStats::EVENT_COPY_ERR, msg->event_type);
            AuthorizeESEvent(clt, msg, getDefaultESResponse(msg));
            return;
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            CloudBlocker::GetInstance().HandleEvent(clt, msgCopy);
            es_free_message(msgCopy);
        });
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
        g_logger.log(LogLevel::ERR, DEBUG_ARGS, "es_clear_cache: ", resCache);
        return false;
    }

    // Don't constantly report writes to current /dev/tty
    es_mute_path_literal(m_clt, [NSProcessInfo.processInfo.arguments[0] UTF8String]);

    // Subscribe to the events we're interested in
    es_return_t subscribed = es_subscribe(m_clt,
                                          m_eventsOfInterest.data(),
                                          static_cast<uint32_t>(m_eventsOfInterest.size()));
    if (subscribed == ES_RETURN_ERROR) {
        g_logger.log(LogLevel::ERR, DEBUG_ARGS, "es_subscribe: ES_RETURN_ERROR");
        return false;
    }

    return true;
}

void CloudBlocker::Uninit()
{
    if(m_clt) {
        es_unsubscribe_all(m_clt);
        es_delete_client(m_clt);
        m_clt = nullptr;
    }
}

bool CloudBlocker::Configure(const std::unordered_map<CloudProviderId, BlockLevel> &config)
{
    std::scoped_lock<std::mutex> lock(m_configMtx);

    struct stat info;
    if (lstat(_PATH_CONSOLE, &info)) {
        g_logger.log(LogLevel::ERR, DEBUG_ARGS, "Could not get the active user");
        return false;
    }

    const struct passwd * const pwd = getpwuid(info.st_uid);
    if (pwd == nullptr)  {
        g_logger.log(LogLevel::ERR, DEBUG_ARGS, "Could not get user information from UID");
        return false;
    }
    const std::string homePath = "/Users/" + std::string(pwd->pw_name);

    std::vector<std::string> paths;
    for (const auto &[cpId, blkLvl] : config) {
        switch (cpId) {
            case CloudProviderId::ICLOUD:
            {
                paths = ICloud::FindPaths(homePath);
                m_config[cpId] = ICloud(blkLvl, paths);
                break;
            }
            case CloudProviderId::DROPBOX:
            {
                paths = Dropbox::FindPaths(homePath);
                m_config[cpId] = Dropbox(blkLvl, paths);
                break;
            }
            default:
                break;
        }

        if (paths.empty())
            g_logger.log(LogLevel::ERR, DEBUG_ARGS, "Could not set ", g_cpToStr.at(cpId), " paths.");
        for (const auto &path : paths)
            g_logger.log(LogLevel::INFO, DEBUG_ARGS, g_cpToStr.at(cpId), ": Path set to \"", path, "\".");
    }
    return true;
}

std::ostream & operator << (std::ostream &out, const CloudBlocker::Stats &stats)
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


// MARK: - Private
void CloudBlocker::IncreaseStats(const CloudBlockerStats metric, const es_event_type_t type, const uint64_t count)
{
    std::scoped_lock<std::mutex> lock(m_statsMtx);
    switch (metric)
    {
        case CloudBlockerStats::EVENT_COPY_ERR:
            m_stats.eventStats[type].copyErr += count;
            break;
        case CloudBlockerStats::EVENT_DROPPED_KERNEL:
            m_stats.eventStats[type].droppedKernel += count; // TODO: take ignored events into account
            break;
        case CloudBlockerStats::EVENT_DROPPED_DEADLINE:
            m_stats.eventStats[type].droppedDeadline += count;
            break;
    }
}

std::optional<std::reference_wrapper<const CloudProvider>> CloudBlocker::ResolveCloudProvider(const std::vector<const std::string> &eventPaths)
{
    // TODO: recognize copy from one CloudProvider to another one
    // TODO: check thread safety of m_config and the returned CloudProvider
    // TODO: make it more effective
    // For every cloud provider
    for (const auto &[cpId,cp] : m_config) {
        // For every path in the event
        for (const auto &eventPath : eventPaths) {
            // Check if the event path is one of cloud provider paths
            for (const auto &cpPath : cp.paths) {
                if (eventPath.find(cpPath) != std::string::npos) {
                    return cp;
                }
            }
        }
    }

    return std::nullopt;
}

void CloudBlocker::AuthorizeESEvent(es_client_t * const clt, const es_message_t * const msg, const std::any &result)
{
    // Handle subscribed AUTH events
    es_respond_result_t ret;
    if (msg->event_type == ES_EVENT_TYPE_AUTH_OPEN)
        ret = es_respond_flags_result(clt, msg, std::any_cast<uint32_t>(result), false);
    else
        ret = es_respond_auth_result(clt, msg, std::any_cast<es_auth_result_t>(result), false);

    if (ret != ES_RESPOND_RESULT_SUCCESS)
        g_logger.log(LogLevel::ERR, DEBUG_ARGS, "Error es_respond_auth_result: ", g_respondResultToStrMap.at(ret));
}

std::any CloudBlocker::HandleEventImpl(const es_message_t * const msg)
{
    if (msg == nullptr) {
        g_logger.log(LogLevel::ERR, DEBUG_ARGS, "Got nullptr!");
        return std::nullopt;
    }

    // Dirty temporary hack.
    // Set default non-destructive return. AUTH_OPEN returns flags, other auth events return AUTH_RESULT and notify does not care.
    std::any ret = getDefaultESResponse(msg);

    // At first get some metrics
    // std::scoped_lock<std::mutex> lock(m_statsMtx); // !!!: causes deadlock. Fix thread safety!
    Stats::EventStats &eventStats = m_stats.eventStats[msg->event_type];
    // if it's the first event of its type don't check seq_num sequence
    if (unlikely(eventStats.firstEvent == true)) {
        eventStats.firstEvent = false;
    } // if we already had any event of its type and the sequence is broken we dropped an event
    else if (unlikely((eventStats.lastSeqNum + 1) != msg->seq_num)) {
        g_logger.log(LogLevel::WARNING, DEBUG_ARGS, "Event dropped!");
        IncreaseStats(CloudBlockerStats::EVENT_DROPPED_KERNEL, msg->event_type, msg->seq_num - eventStats.lastSeqNum);
    } // else everything is ok

    // set the new lastSeq
    eventStats.lastSeqNum = msg->seq_num;

    // !!!: This call WILL crash if called with unsupported event type
    const std::vector<const std::string> eventPaths = paths_from_event(msg);

    const auto cp = ResolveCloudProvider(eventPaths);
    // Not a supported cloud provider, ignore the event.
    if (!cp.has_value())
        return ret;

    return cp->get().HandleEvent(msg);
}

// MARK: Callbacks
void CloudBlocker::HandleEvent(es_client_t * const clt, const es_message_t * const msg)
{
    try {
        if (msg == nullptr) {
            g_logger.log(LogLevel::ERR, DEBUG_ARGS, "Received null argument");
            return;
        }

        uint64_t msecDeadline = mach_time_to_msecs(msg->deadline);
        // Set deadline a bit sooner
        const std::chrono::milliseconds f_msecDeadline { msecDeadline - (msecDeadline >> 3) }; // substract 12.5%
        std::any result = getDefaultESResponse(msg);

        std::future<std::any> f = std::async(std::launch::async, &CloudBlocker::HandleEventImpl, this, msg);
        const std::future_status f_res = f.wait_until(std::chrono::steady_clock::now() + f_msecDeadline);

        // If it's an NOTIFY event, we do not need to do anything. Just return.
        if (msg->action_type == ES_ACTION_TYPE_NOTIFY)
            return;

        // We timed out.
        if (f_res != std::future_status::ready) {
            g_logger.log(LogLevel::WARNING, DEBUG_ARGS, "Event dropped because of deadline (or deferred)! <", static_cast<unsigned int>(f_res), ">");
            IncreaseStats(CloudBlockerStats::EVENT_DROPPED_DEADLINE, msg->event_type);
        } else if (!f.valid()) {
                g_logger.log(LogLevel::ERR, DEBUG_ARGS, "Future is not in a valid state!");
        } else {
            std::any resultTmp = f.get();

            if (!resultTmp.has_value())
                g_logger.log(LogLevel::ERR, DEBUG_ARGS, "HandleEventImpl did not return a value!!");
            else
                result = resultTmp;
        }

        AuthorizeESEvent(clt, msg, result);

    } catch (const std::exception &e) {
        g_logger.log(LogLevel::ERR, DEBUG_ARGS, e.what());
    }
    catch (...) {
        g_logger.log(LogLevel::ERR, DEBUG_ARGS, "Unknown exception!");
    }
}

void CloudBlocker::PrintStats()
{
    std::scoped_lock<std::mutex> lock(m_statsMtx);
    std::cout << m_stats << std::endl;
}

CloudBlocker& CloudBlocker::GetInstance()
{
    static CloudBlocker cloudBlocker;
    return cloudBlocker;
}
