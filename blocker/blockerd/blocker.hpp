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

enum class BlockerStats : uint8_t
{
    EVENT_COPY_ERR,
    EVENT_DROPPED_KERNEL,
    EVENT_DROPPED_DEADLINE,
};

enum class BlockLevel : uint8_t
{
    NONE,
    RONLY,
    FULL,
};

enum class CloudProviderId : uint8_t
{
    NONE,
    ICLOUD,
    DROPBOX,
    ONEDRIVE,
    //Google Drive File Stream
};
extern const std::unordered_map<CloudProviderId, const std::string> g_cpToStr;

struct CloudProvider
{
    CloudProviderId id = CloudProviderId::NONE;
    BlockLevel bl = BlockLevel::NONE;
    std::vector<std::string> paths;
    std::vector<std::string> allowedBundleIds;

    CloudProvider() = default;
    virtual ~CloudProvider() = default;
    // delete copy operations
    CloudProvider(const CloudProvider &) = delete;
    void operator=(const CloudProvider &) = delete;
    // move operations
    CloudProvider(CloudProvider&& other)
    {
        id = other.id;
        bl = other.bl;
        paths = std::move(other.paths);
        allowedBundleIds = std::move(other.allowedBundleIds);

        other.id = CloudProviderId::NONE;
        other.bl = BlockLevel::NONE;
        other.paths.clear();
        other.allowedBundleIds.clear();
    }

    CloudProvider& operator=(CloudProvider&& other)
    {
        if (this == &other)
            return *this;

        id = other.id;
        bl = other.bl;
        paths = std::move(other.paths);
        allowedBundleIds = std::move(other.allowedBundleIds);

        other.id = CloudProviderId::NONE;
        other.bl = BlockLevel::NONE;
        other.paths.clear();
        other.allowedBundleIds.clear();

        return *this;
    }

    bool BundleIdIsAllowed(const es_string_token_t bundleId) const;
};

struct ICloud : public CloudProvider
{
    ICloud(const BlockLevel Bl, const std::vector<std::string> &Paths) {
        id = CloudProviderId::ICLOUD;
        bl = Bl;
        paths = Paths;
        allowedBundleIds = {
            "com.apple.bird",
        };
    };
    ~ICloud() = default;
};

struct Dropbox : public CloudProvider
{
    Dropbox(const BlockLevel Bl, const std::vector<std::string> &Paths) {
        id = CloudProviderId::ICLOUD;
        bl = Bl;
        paths = Paths;
        allowedBundleIds = {
            //"",
        };
    };
    ~Dropbox() = default;
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
    Stats m_stats;

    std::optional<std::reference_wrapper<const CloudProvider>> ResolveCloudProvider(const std::vector<const std::string> &paths);

    // MARK: Callbacks
    std::any HandleEventImpl(const es_message_t * const msg);


    // MARK: - Public
public:
    std::unordered_map<CloudProviderId, CloudProvider> m_config;
    const std::vector<es_event_type_t> m_eventsOfInterest = {
        // File System
        ES_EVENT_TYPE_AUTH_CLONE,
        ES_EVENT_TYPE_AUTH_CREATE,
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

    // MARK: Stats
    void IncreaseStats(const BlockerStats metric, const es_event_type_t type, const uint64_t count = 1);

    // MARK: Callbacks
    void HandleEvent(es_client_t * const clt, es_message_t * const msg);

    // MARK: Logging
    friend std::ostream & operator << (std::ostream &out, const Blocker::Stats &stats);
    void PrintStats();
};

#endif /* blocker_hpp */
