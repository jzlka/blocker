//
//  blocker.hpp
//  blockerd
//
//  Created by Jozef on 19/05/2020.
//  Copyright © 2020 Jozef Zuzelka. All rights reserved.
//

#ifndef blocker_hpp
#define blocker_hpp

#include <cstdint>
#include <map>
#include <mutex>
#include <vector>
#include <string>
#include <EndpointSecurity/ESTypes.h>

enum class BlockLevel : uint8_t
{
    NONE,
    RONLY,
    FULL,
};

enum class CloudProvider : uint8_t
{
    UNKNOWN,
    ICLOUD,
    DROPBOX,
    ONEDRIVE,
    //Google Drive File Stream
};

enum class BlockerStats : uint8_t
{
    EVENT_COPY_ERR,
    EVENT_DROPPED_KERNEL,
    EVENT_DROPPED_DEADLINE,
};

class Blocker
{
    struct Stats {
        int copyErr         = 0;
        int droppedKernel   = 0;
        int droppedDeadline = 0;
    };

    es_client_t *m_clt      = nullptr;
    std::mutex m_mtx;
    Stats m_stats;

public:
    std::map<CloudProvider, BlockLevel> m_config;
    std::vector<es_event_type_t> m_eventsOfInterest = {
        // Process
        ES_EVENT_TYPE_AUTH_EXEC,
        ES_EVENT_TYPE_NOTIFY_EXIT,
        ES_EVENT_TYPE_NOTIFY_FORK,
        // File System
        ES_EVENT_TYPE_NOTIFY_ACCESS,
        ES_EVENT_TYPE_AUTH_CLONE,
        ES_EVENT_TYPE_NOTIFY_CLOSE,
        ES_EVENT_TYPE_AUTH_CREATE,
        ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE,
        ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE,
        ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA,
        ES_EVENT_TYPE_AUTH_LINK,
        ES_EVENT_TYPE_AUTH_MOUNT,
        ES_EVENT_TYPE_AUTH_OPEN,
        ES_EVENT_TYPE_AUTH_READDIR,
        ES_EVENT_TYPE_AUTH_READLINK,
        ES_EVENT_TYPE_AUTH_RENAME,
        ES_EVENT_TYPE_AUTH_TRUNCATE,
        ES_EVENT_TYPE_AUTH_UNLINK,
        ES_EVENT_TYPE_NOTIFY_UNMOUNT,
        ES_EVENT_TYPE_NOTIFY_WRITE,
        // System
        ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN,
        ES_EVENT_TYPE_NOTIFY_KEXTLOAD,
        ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD,
    };

    std::vector<const std::string> m_blockedPaths; // TODO: thread safety


    Blocker() = default;
    ~Blocker() = default;
    // delete copy operations
    Blocker(const Blocker &) = delete;
    void operator=(const Blocker &) = delete;

    static Blocker& GetInstance();
    bool Init();
    bool Uninit();


    // MARK: Callbacks
    void HandleEvent(es_client_t * const clt, const es_message_t *msg);
    void HandleNotifyEvent(const es_message_t *msg);

    // MARK: Stats
    void IncreaseStats(const BlockerStats type, int count = 1);
};

#endif /* blocker_hpp */
