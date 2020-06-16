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

    static std::vector<std::string> FindPaths(const std::string &homePath);
    es_auth_result_t AuthWriteGeneral(const std::string &bundleId, const std::vector<std::string> &cpPaths, const es_message_t * const msg) const override;
    uint32_t AuthOpen(const std::string &bundleId,const  std::vector<std::string> &cpPaths, const uint32_t fflags) const override;
private:
    bool ContainsDropboxCacheFolder(const std::vector<std::string> &eventPaths) const;
};

#endif /* dropbox_hpp */
