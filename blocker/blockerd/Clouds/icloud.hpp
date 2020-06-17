//
//  icloud.hpp
//  blockerd
//
//  Created by Jozef on 05/06/2020.
//  Copyright © 2020 Jozef Zuzelka. All rights reserved.
//

#ifndef icloud_hpp
#define icloud_hpp

#include "base.hpp"

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

    // delete copy operations
    ICloud(const ICloud &) = delete;
    void operator=(const ICloud &) = delete;
    // move operations
    ICloud(ICloud&& other)
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

    ICloud& operator=(ICloud&& other)
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

    static std::vector<std::string> FindPaths(const std::string &homePath);
    es_auth_result_t AuthWriteGeneral(const std::string &bundleId, const std::vector<std::string> &cpPaths, const es_message_t * const msg) const override;
    uint32_t AuthOpen(const std::string &bundleId,const  std::vector<std::string> &cpPaths, const uint32_t fflags) const override;
};

#endif /* icloud_hpp */
