//
//  blocker.hpp
//  blockerd
//
//  Created by Jozef on 19/05/2020.
//  Copyright © 2020 Jozef Zuzelka. All rights reserved.
//

#ifndef blocker_hpp
#define blocker_hpp

#include <any>
#include <cstdint>
#include <EndpointSecurity/EndpointSecurity.h>
#include <functional>
#include <unordered_map>
#include <mutex>
#include <string>
#include <vector>

#include "Clouds/base.hpp"

extern const std::unordered_map<BlockLevel, const std::string> g_blockLvlToStr;

enum class BlockerStats : uint8_t
{
    EVENT_COPY_ERR,
    EVENT_DROPPED_KERNEL,
    EVENT_DROPPED_DEADLINE,
};

class Blocker
{
    struct Stats {
        struct EventStats {
            uint64_t firstEvent      = true;
            uint64_t lastSeqNum      = 0;
            uint64_t copyErr         = 0;
            uint64_t droppedKernel   = 0;
            uint64_t droppedDeadline = 0;
        };

        std::unordered_map<es_event_type_t, EventStats> eventStats;
    };

    es_client_t *m_clt = nullptr;
    std::mutex m_statsMtx;
    std::mutex m_configMtx;
    Stats m_stats;

    std::optional<std::reference_wrapper<const CloudProvider>> ResolveCloudProvider(const std::vector<const std::string> &eventPaths);

    void AuthorizeESEvent(es_client_t * const clt, const es_message_t * const msg, const std::any &result);
    // MARK: Callbacks
    std::any HandleEventImpl(const es_message_t * const msg);


    // MARK: - Public
public:
    std::unordered_map<CloudProviderId, CloudProvider> m_config;
    const std::vector<es_event_type_t> m_eventsOfInterest = {
        // File System
        ES_EVENT_TYPE_AUTH_CLONE,
        ES_EVENT_TYPE_AUTH_CREATE,
        ES_EVENT_TYPE_AUTH_CHDIR,
        ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE,
        ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE,
        ES_EVENT_TYPE_AUTH_LINK,
        ES_EVENT_TYPE_AUTH_MOUNT,
        ES_EVENT_TYPE_AUTH_OPEN,
        ES_EVENT_TYPE_AUTH_READDIR,
        ES_EVENT_TYPE_AUTH_READLINK,
        ES_EVENT_TYPE_AUTH_RENAME,
        ES_EVENT_TYPE_AUTH_TRUNCATE,
        ES_EVENT_TYPE_AUTH_UNLINK,
        ES_EVENT_TYPE_NOTIFY_ACCESS,
        ES_EVENT_TYPE_NOTIFY_CLOSE,
        ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA,
        ES_EVENT_TYPE_NOTIFY_UNMOUNT,
        ES_EVENT_TYPE_NOTIFY_WRITE,
    };

    Blocker() = default;
    ~Blocker() = default;
    // delete copy operations
    Blocker(const Blocker &) = delete;
    void operator=(const Blocker &) = delete;

    static Blocker& GetInstance();
    bool Init();
    void Uninit();
    bool Configure(const std::unordered_map<CloudProviderId, BlockLevel> &config);

    // MARK: Stats
    void IncreaseStats(const BlockerStats metric, const es_event_type_t type, const uint64_t count = 1);

    // MARK: Callbacks
    void HandleEvent(es_client_t * const clt, const es_message_t * const msg);

    // MARK: Logging
    friend std::ostream & operator << (std::ostream &out, const Blocker::Stats &stats);
    void PrintStats();
};

#endif /* blocker_hpp */
