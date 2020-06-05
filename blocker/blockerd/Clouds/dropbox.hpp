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
        id = CloudProviderId::ICLOUD;
        bl = Bl;
        paths = Paths;
        allowedBundleIds = {
            //"com.getdropbox.dropbox",
        };
    };
    ~Dropbox() = default;

    static std::vector<std::string> FindPaths(const std::string &homePath);
};

#endif /* dropbox_hpp */
