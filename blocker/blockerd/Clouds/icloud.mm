//
//  icloud.cpp
//  blockerd
//
//  Created by Jozef on 05/06/2020.
//  Copyright © 2020 Jozef Zuzelka. All rights reserved.
//

#include "icloud.hpp"

std::vector<std::string> ICloud::FindPaths(const std::string &homePath)
{
    return { homePath + "/Library/Mobile Documents" }; // $HOME/Library/Mobile Documents/com~apple~CloudDocs
}

es_auth_result_t ICloud::AuthWriteGeneral(const std::string &bundleId, const std::vector<std::string> &cpPaths, const es_message_t * const msg) const
{
    return CloudProvider::AuthWriteGeneral(bundleId, cpPaths, msg);
}

uint32_t ICloud::AuthOpen(const std::string &bundleId,const  std::vector<std::string> &cpPaths, const uint32_t fflags) const
{
    return CloudProvider::AuthOpen(bundleId, cpPaths, fflags);
}
