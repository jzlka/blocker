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
#include <mach/mach.h>  // panic

#include "../../../Common/Tools/Tools-ES.hpp"
#include "../../../Common/logger.hpp"
#include "dropbox.hpp"

static Logger &g_logger = Logger::getInstance();

std::vector<std::string> Dropbox::FindPaths(const std::string &homePath)
{
    std::string path;


    const std::string configFile = homePath + "/.dropbox/info.json";
    std::ifstream dropboxInfo(configFile);
    if (!dropboxInfo.is_open()) {
        g_logger.log(LogLevel::ERR, DEBUG_ARGS, "Dropbox: Could not open config file ", configFile);
        return {};
    }

    const std::regex pathRegex("\"path\": \"(.*)\","); // TODO: If the path contains ", we are f...
    std::smatch pathMatch;
    std::string line;
    int i = 0;
    while (std::getline(dropboxInfo, line))
    {
        if (++i > 1)
            panic("Needs to be implemented: Dropbox configuration has more than one line!");

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
        path = pathMatch[1];
    }
    return { path };
}
