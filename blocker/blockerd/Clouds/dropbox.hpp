//
//  dropbox.hpp
//  blockerd
//
//  Created by Jozef on 05/06/2020.
//  Copyright © 2020 Jozef Zuzelka. All rights reserved.
//

#ifndef dropbox_hpp
#define dropbox_hpp

#include "base.hpp"

struct Dropbox : public CloudProvider
{
    Dropbox(const BlockLevel Bl, const std::vector<std::string> &Paths) {
        id = CloudProviderId::DROPBOX;
        bl = Bl;
        paths = Paths;
        allowedBundleIds = {
            //"com.getdropbox.dropbox",
        };
    };
    ~Dropbox() = default;

    // delete copy operations
    Dropbox(const Dropbox &) = delete;
    void operator=(const Dropbox &) = delete;
    // move operations
    Dropbox(Dropbox&& other)
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

    Dropbox& operator=(Dropbox&& other)
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
    bool ContainsDropboxCacheFolder(const std::vector<std::string> &eventPaths) const;

    es_auth_result_t AuthWriteGeneral(const std::string &bundleId, const std::vector<std::string> &cpPaths, const es_message_t * const msg) const override;
    uint32_t AuthOpen(const std::string &bundleId,const  std::vector<std::string> &cpPaths, const uint32_t fflags) const override;
};

#endif /* dropbox_hpp */
