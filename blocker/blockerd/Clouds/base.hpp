//
//  base.hpp
//  blockerd
//
//  Created by Jozef on 05/06/2020.
//  Copyright © 2020 Jozef Zuzelka. All rights reserved.
//

#ifndef base_hpp
#define base_hpp

#include <any>
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

struct CloudProvider;
struct CloudInstance
{
    std::reference_wrapper<const CloudProvider> cp;
    std::vector<std::string> eventPaths;
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

    bool BundleIdIsAllowed(const std::string &bundleId) const;

    std::any HandleEvent(const std::string &bundleId, const std::vector<std::string> &cpPaths, const es_message_t * const msg) const;

    std::vector<std::string> FilterCloudFolders(const std::vector<std::string> &eventPaths) const;
protected:
    // Autorization callbacks
    es_auth_result_t         AuthReadGeneral(const std::string &bundleId) const;
    virtual es_auth_result_t AuthWriteGeneral(const std::string &bundleId, const std::vector<std::string> &cpPaths, const es_message_t * const msg) const;
    virtual uint32_t         AuthOpen(const std::string &bundleId,const  std::vector<std::string> &cpPaths, const uint32_t fflags) const;
};


#endif /* base_hpp */
