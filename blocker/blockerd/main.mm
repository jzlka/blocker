//
//  main.mm
//  blockerd
//
//  Created by Jozef on 15/05/2020.
//  Copyright © 2020 Jozef Zuzelka. All rights reserved.
//
// todo:     es_mute_path_literal(endpointClient, [NSProcessInfo.processInfo.arguments[0] UTF8String]);

// Source: https://gist.github.com/Omar-Ikram/8e6721d8e83a3da69b31d4c2612a68ba/


#include <algorithm>
#include <atomic>
#include <bsm/libbsm.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <future>
#include <iostream>
#include <map>
#include <signal.h>
#include <sys/fcntl.h> // FREAD, FWRITE, FFLAGS
#include <vector>
#import <Foundation/Foundation.h>

#include "../../Common/Tools/Tools.hpp"
#include "../../Common/Tools/Tools-ES.hpp"

#include "blocker.hpp"

// From <Kernel/sys/fcntl.h>
/* convert from open() flags to/from fflags; convert O_RD/WR to FREAD/FWRITE */
#define FFLAGS(oflags)  ((oflags) + 1)
#define OFLAGS(fflags)  ((fflags) - 1)
#define MSEC_PER_SEC 1000 /* millisecond per second */

es_client_t *g_client = nullptr;
std::atomic<bool> g_shouldStop = false;

void notify_event_handler(const es_message_t *msg);
uint32_t flags_event_handler(const es_message_t *msg);
es_auth_result_t auth_event_handler(const es_message_t *msg);

void signalHandler(int signum)
{
    g_shouldStop = true;

    if(g_client) {
        es_unsubscribe_all(g_client);
        es_delete_client(g_client);
    }

    // Not safe, but whatever
    std::cerr << "Interrupt signal (" << signum << ") received, exiting." << std::endl;
    exit(signum);
}


int main() {
    // No runloop, no problem
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGABRT, signalHandler);

    const char* demoName = "ESF";
    const std::string demoPath = "/tmp/" + std::string(demoName) + "-demo";

    std::cout << "(" << demoName << ") Hello, World!\n";
    std::cout << "Point of interest: " << demoPath << std::endl << std::endl;


    @autoreleasepool {
        Blocker &blocker = Blocker::GetInstance();
        blocker.m_blockedPaths.push_back(demoPath);

        es_handler_block_t handler = ^(es_client_t *clt, const es_message_t *msg) {
            es_message_t * msgCopy = es_copy_message(msg);
            if (msgCopy == nullptr) {
                std::cerr << "Could not copy message." << std::endl;
                blocker.IncreaseStats(BlockerStats::EVENT_COPY_ERR);
                return;
            }

            dispatch_async(dispatch_get_main_queue(), ^{
                Blocker &blocker_local = Blocker::GetInstance();
                const std::chrono::milliseconds f_msecDeadline { mach_time_to_msecs(msg->deadline) - MSEC_PER_SEC };

                // TODO: throws an exception
                std::future f = std::async(std::launch::async, [clt,msg]{ Blocker::GetInstance().HandleEvent(clt, msg); });

                // Set deadline to one second sooner
                const auto f_res = f.wait_until(std::chrono::steady_clock::now() + std::chrono::duration_cast<std::chrono::seconds>(f_msecDeadline));
                if (f_res == std::future_status::timeout)
                    blocker_local.IncreaseStats(BlockerStats::EVENT_DROPPED_DEADLINE);

                // AppleDoc: Warning: Freeing a message from inside a handler block will cause your app to crash.
                // But as this block is running async from the original block, freeing should be OK.
                es_free_message(msgCopy);
            });
        };

        es_new_client_result_t res = es_new_client(&g_client, handler);

        // Handle any errors encountered while creating the client.
        if (ES_NEW_CLIENT_RESULT_SUCCESS != res) {
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

            return EXIT_FAILURE;
        }

        // Cache needs to be explicitly cleared between program invocations
        es_clear_cache_result_t resCache = es_clear_cache(g_client);
        if (ES_CLEAR_CACHE_RESULT_SUCCESS != resCache) {
            std::cerr << "es_clear_cache: " << resCache << std::endl;
            return EXIT_FAILURE;
        }


        // Subscribe to the events we're interested in
        es_return_t subscribed = es_subscribe(g_client,
                                              blocker.m_eventsOfInterest.data(),
                                              blocker.m_eventsOfInterest.size()
                                              );

        if (subscribed == ES_RETURN_ERROR) {
            std::cerr << "es_subscribe: ES_RETURN_ERROR\n";
            return EXIT_FAILURE;
        }

        dispatch_main();
    }

    return EXIT_SUCCESS;
}


static const auto find_occurence = [](const std::string& str) {
        return false;
};

void notify_event_handler(const es_message_t *msg)
{
    switch(msg->event_type) {
        // Process
        case ES_EVENT_TYPE_NOTIFY_EXIT:
        case ES_EVENT_TYPE_NOTIFY_FORK:
        // System
        case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN:
            break;
        case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
        case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD:
        // File System
        case ES_EVENT_TYPE_NOTIFY_UNMOUNT:
            std::cout << "NOTIFY OPERATION: " << g_eventTypeToStrMap.at(msg->event_type) << std::endl;
            std::cout << msg << std::endl;
            break;
        // File System
        case ES_EVENT_TYPE_NOTIFY_ACCESS:
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
        case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
        case ES_EVENT_TYPE_NOTIFY_WRITE:
        {
            const std::vector<const std::string> eventPaths = paths_from_file_event(msg);

            // Block if path is in our blocked paths list
            if (std::any_of(eventPaths.cbegin(), eventPaths.cend(), find_occurence)) {
                std::cout << "    " << (msg->action_type == ES_ACTION_TYPE_AUTH ? "BLOCKING: " : "NOTIFY: ")
                          << g_eventTypeToStrMap.at(msg->event_type) << " at "
                          << (long long) msg->mach_time << " of mach time." << std::endl;
                std::cout << msg << std::endl;
            }
            break;
        }
        default:
            std::cout << "DEFAULT: " << g_eventTypeToStrMap.at(msg->event_type) << std::endl;
            break;
    }
}

uint32_t flags_event_handler(const es_message_t *msg)
{
    uint32_t res = msg->event.open.fflag;

    switch(msg->event_type) {
        case ES_EVENT_TYPE_AUTH_OPEN:
        {
            const std::vector<const std::string> eventPaths = paths_from_file_event(msg);

            // Block if path is in our blocked paths list
            if (std::any_of(eventPaths.cbegin(), eventPaths.cend(), find_occurence)) {
                std::cout << "    " << (msg->action_type == ES_ACTION_TYPE_AUTH ? "BLOCKING: " : "NOTIFY: ")
                          << g_eventTypeToStrMap.at(msg->event_type) << " at "
                          << (long long) msg->mach_time << " of mach time." << std::endl;
                std::cout << msg << std::endl;
                res = FFLAGS(O_RDONLY);
            }
            break;
        }
        default:
            std::cout << "DEFAULT: " << g_eventTypeToStrMap.at(msg->event_type) << std::endl;
            break;
    }

    return res;
}

// Simple handler to make AUTH (allow or block) decisions.
// Returns either an ES_AUTH_RESULT_ALLOW or ES_AUTH_RESULT_DENY.
es_auth_result_t auth_event_handler(const es_message_t *msg)
{
    switch(msg->event_type) {
        // Process
        case ES_EVENT_TYPE_AUTH_EXEC:
            break;
        // System
        // File System
        case ES_EVENT_TYPE_AUTH_MOUNT:
            std::cout << "ALLOWING OPERATION: " << g_eventTypeToStrMap.at(msg->event_type) << std::endl;
            std::cout << msg << std::endl;
            break;
        // File System
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
            const std::vector<const std::string> eventPaths = paths_from_file_event(msg);

            // Block if path is in our blocked paths list
            if (std::any_of(eventPaths.cbegin(), eventPaths.cend(), find_occurence)) {
                std::cout << "    " << (msg->action_type == ES_ACTION_TYPE_AUTH ? "BLOCKING: " : "NOTIFY: ")
                          << g_eventTypeToStrMap.at(msg->event_type) << " at "
                          << (long long) msg->mach_time << " of mach time." << std::endl;
                std::cout << msg << std::endl;

                return ES_AUTH_RESULT_DENY;
            }
            break;
        }
        default:
            std::cout << "DEFAULT: " << g_eventTypeToStrMap.at(msg->event_type) << std::endl;
            break;
    }

    return ES_AUTH_RESULT_ALLOW;
}
