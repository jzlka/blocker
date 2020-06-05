//
//  base.hpp
//  blockerd
//
//  Created by Jozef on 05/06/2020.
//  Copyright © 2020 Jozef Zuzelka. All rights reserved.
//

#ifndef base_hpp
#define base_hpp

#include <EndpointSecurity/EndpointSecurity.h>
#include <string>
#include <unordered_map>
#include <vector>


enum class CloudProviderId : uint8_t
{
    NONE,
    ICLOUD,
    DROPBOX,
    ONEDRIVE,
    //Google Drive File Stream
};

enum class BlockLevel : uint8_t
{
    NONE,
    RONLY,
    FULL,
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

    // Autorization callbacks
    es_auth_result_t AuthReaddir(const es_message_t * const msg) const;
    es_auth_result_t AuthRename(const es_message_t * const msg) const;
    es_auth_result_t AuthCreate(const es_message_t * const msg) const;
    uint32_t         AuthOpen(const es_message_t * const msg) const;

private:
    bool ContainsDropboxCacheFolder(const std::vector<const std::string> &eventPaths) const;
};


#endif /* base_hpp */
