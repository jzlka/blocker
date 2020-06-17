//
//  dropbox.cpp
//  blockerd
//
//  Created by Jozef on 05/06/2020.
//  Copyright © 2020 Jozef Zuzelka. All rights reserved.
//

#include <fstream>
#include <regex>
#include <sstream>

#include "../../../Common/Tools/Tools-ES.hpp"
#include "../../../Common/logger.hpp"
#include "dropbox.hpp"

static Logger &g_logger = Logger::getInstance();

std::vector<std::string> Dropbox::FindPaths(const std::string &homePath)
{
    std::vector<std::string> paths;


    const std::string configFile = homePath + "/.dropbox/info.json";
    std::ifstream dropboxInfo(configFile);
    if (!dropboxInfo.is_open()) {
        g_logger.log(LogLevel::ERR, DEBUG_ARGS, "Dropbox: Could not open config file ", configFile);
        return {};
    }

    const std::regex pathRegex("\"path\": \"(.*)\","); // TODO: If the path contains ", we are f...
    std::smatch pathMatch;
    std::string line;
    while (std::getline(dropboxInfo, line))
    {
        std::istringstream iss(line);
        g_logger.log(LogLevel::VERBOSE, DEBUG_ARGS, "Dropbox: config read: ", line);

        if (!std::regex_search(line, pathMatch, pathRegex)) {
            g_logger.log(LogLevel::ERR, DEBUG_ARGS, "Dropbox: Regex search failed.");
            return {};
        }

        if (pathMatch.size() != 2) {
            g_logger.log(LogLevel::ERR, DEBUG_ARGS, "Dropbox: No match found in path regex.");
            return {};
        }

        g_logger.log(LogLevel::VERBOSE, DEBUG_ARGS, "Dropbox: match[0] ", pathMatch[0], " match[1] ", pathMatch[1]);
        paths.push_back(pathMatch[1]);
    }
    return paths;
}

bool Dropbox::ContainsDropboxCacheFolder(const std::vector<std::string> &eventPaths) const
{
    for (const auto &dropboxPath : paths) {
        const std::string dropboxCache = dropboxPath + "/.dropbox.cache";

        for (const auto &eventPath : eventPaths)
            if (eventPath.find(dropboxCache) != std::string::npos)
                return true;
    }
    return false;
}


es_auth_result_t Dropbox::AuthWriteGeneral(const std::string &bundleId, const std::vector<std::string> &cpPaths, const es_message_t * const msg) const
{
    const std::string dropboxBundleId = "com.getdropbox.dropbox";
    // If the operation is from/to one of Dropbox folders, allow it.
    // !!!: we expect that the Dropbox cache folder is not accesible using Dropbox file explorer (which is true so far) so an user cannot do any mess there using the Dropbox app.
    if (bundleId == dropboxBundleId && ContainsDropboxCacheFolder(cpPaths)) {
        g_logger.log(LogLevel::VERBOSE, DEBUG_ARGS, "Ignoring Dropbox process.");
        return ES_AUTH_RESULT_ALLOW;
    }

    return CloudProvider::AuthWriteGeneral(bundleId, cpPaths, msg);
}

uint32_t Dropbox::AuthOpen(const std::string &bundleId,const  std::vector<std::string> &cpPaths, const uint32_t fflags) const
{
    const std::string dropboxBundleId = "com.getdropbox.dropbox";
    // If the operation is from/to one of Dropbox cache folders, allow it.
    // !!!: we expect that the Dropbox cache folder is not accesible using Dropbox file explorer (which is true so far) so an user cannot do any mess there using the Dropbox app.
    if (bundleId == dropboxBundleId && ContainsDropboxCacheFolder(cpPaths))
        return ES_AUTH_RESULT_ALLOW;

    return CloudProvider::AuthOpen(bundleId, cpPaths, fflags);
}
