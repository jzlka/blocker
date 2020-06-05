//
//  cloudblocker.hpp
//  blockerd
//
//  Created by Jozef on 05/06/2020.
//  Copyright © 2020 Jozef Zuzelka. All rights reserved.
//

#ifndef cloudblocker_hpp
#define cloudblocker_hpp

enum class CloudBlockerStats : uint8_t
{
    EVENT_COPY_ERR,
    EVENT_DROPPED_KERNEL,
    EVENT_DROPPED_DEADLINE,
};

class CloudBlocker
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

    es_client_t *m_clt = nullptr;
    Stats m_stats;
    std::mutex m_statsMtx;
    std::unordered_map<CloudProviderId, CloudProvider> m_config;
    std::mutex m_configMtx;

    std::optional<std::reference_wrapper<const CloudProvider>> ResolveCloudProvider(const std::vector<const std::string> &eventPaths);

    void AuthorizeESEvent(es_client_t * const clt, const es_message_t * const msg, const std::any &result);

    std::any HandleEventImpl(const es_message_t * const msg);

    void IncreaseStats(const CloudBlockerStats metric, const es_event_type_t type, const uint64_t count = 1);


    // MARK: Callbacks
    void HandleEvent(es_client_t * const clt, const es_message_t * const msg);

    // MARK: Logging
    friend std::ostream & operator << (std::ostream &out, const CloudBlocker::Stats &stats);

public:
    CloudBlocker() = default;
    ~CloudBlocker() = default;
    // delete copy operations
    CloudBlocker(const CloudBlocker &) = delete;
    void operator=(const CloudBlocker &) = delete;

    static CloudBlocker& GetInstance();
    bool Init();
    void Uninit();
    bool Configure(const std::unordered_map<CloudProviderId, BlockLevel> &config);
    void PrintStats();
};


#endif /* cloudblocker_hpp */
