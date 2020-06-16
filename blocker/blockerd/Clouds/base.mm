//
//  base.cpp
//  blockerd
//
//  Created by Jozef on 05/06/2020.
//  Copyright © 2020 Jozef Zuzelka. All rights reserved.
//

#include <any>
#include <bsm/libbsm.h>
#include <EndpointSecurity/EndpointSecurity.h>

#include "../../../Common/Tools/Tools-ES.hpp"
#include "../../../Common/Tools/Tools.hpp"
#include "../../../Common/logger.hpp"
#include "../blocker.hpp"
#include "dropbox.hpp"
#include "base.hpp"

static Logger &g_logger = Logger::getInstance();

const std::unordered_map<CloudProviderId, const std::string> g_cpToStr = {
    {CloudProviderId::NONE,     "NONE"},
    {CloudProviderId::ICLOUD,   "iCloud"},
    {CloudProviderId::DROPBOX,  "Dropbox"},
    {CloudProviderId::ONEDRIVE, "OneDrive"},
};

bool CloudProvider::BundleIdIsAllowed(const std::string &bundleId) const
{
    return (std::find(allowedBundleIds.begin(), allowedBundleIds.end(), bundleId) != allowedBundleIds.end());
}

std::any CloudProvider::HandleEvent(const std::string &bundleId, const std::vector<std::string> &cpPaths, const es_message_t * const msg) const
{
    std::any ret = getDefaultESResponse(msg);

    const auto composeDebugMessage = [&]() {
        std::string msgToPrint = "(" + g_blockLvlToStr.at(bl) + ") ";
        msgToPrint += g_eventTypeToStrMap.at(msg->event_type) + " -";
        if (msg->action_type == ES_ACTION_TYPE_AUTH) {
            if (ret.type() == typeid(es_auth_result_t)) {
                msgToPrint += (std::any_cast<es_auth_result_t>(ret) == ES_AUTH_RESULT_DENY ? (RED " BLOCKING" CLR) : (GRN " ALLOWING" CLR));
            } else if (ret.type() == typeid(uint32_t)) {
                char *allowedFlags = esfflagstostr(std::any_cast<uint32_t>(ret));
                char *blockedFlags = esfflagstostr(std::any_cast<uint32_t>(ret) ^ msg->event.open.fflag);

                msgToPrint += (" ALLOWING (" GRN);
                msgToPrint += (allowedFlags == nullptr ? "null" : allowedFlags);
                msgToPrint += (CLR "), BLOCKING (" RED);
                msgToPrint += (blockedFlags == nullptr ? "null" : blockedFlags);
                msgToPrint += (CLR ")");

                free(allowedFlags);     allowedFlags = nullptr;
                free(blockedFlags);     blockedFlags = nullptr;
            }
        }

        msgToPrint += " operation at";
        for (const auto &path : cpPaths)
            msgToPrint += " '" + path + "'";

        msgToPrint += " by " + to_string(msg->process->signing_id);
        msgToPrint += "(" + std::to_string(audit_token_to_pid(msg->process->audit_token)) + ")";
        return msgToPrint;
    };

    // Bundle is allowed, lets do it its job.
    if (BundleIdIsAllowed(bundleId)) {
        g_logger.log(LogLevel::INFO, DEBUG_ARGS, composeDebugMessage());
        return ret;
    }

    switch(msg->event_type) {
        // MARK: NOTIFY
        case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
        case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD:
        case ES_EVENT_TYPE_NOTIFY_UNMOUNT:
        case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
        case ES_EVENT_TYPE_NOTIFY_WRITE:
            // For debug reasons to uncover when it's called
            g_logger.log(LogLevel::VERBOSE, DEBUG_ARGS, msg);
        case ES_EVENT_TYPE_NOTIFY_ACCESS:
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            break;
        // MARK: AUTH
        case ES_EVENT_TYPE_AUTH_READLINK:
        case ES_EVENT_TYPE_AUTH_CHDIR:
        case ES_EVENT_TYPE_AUTH_READDIR:
            ret = AuthReadGeneral(bundleId);
            break;
        case ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE:
        case ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE:
        case ES_EVENT_TYPE_AUTH_LINK:
        case ES_EVENT_TYPE_AUTH_TRUNCATE:
            // For debug reasons to uncover when it's called
            g_logger.log(LogLevel::VERBOSE, DEBUG_ARGS, msg);
        case ES_EVENT_TYPE_AUTH_CREATE:
        case ES_EVENT_TYPE_AUTH_RENAME:
        case ES_EVENT_TYPE_AUTH_CLONE:
        case ES_EVENT_TYPE_AUTH_UNLINK:
            ret = AuthWriteGeneral(bundleId, cpPaths, msg);
            break;
        case ES_EVENT_TYPE_AUTH_OPEN:
            ret = AuthOpen(bundleId, cpPaths, msg->event.open.fflag);
            break;
        case ES_EVENT_TYPE_AUTH_MOUNT:
            // For debug reasons to uncover when it's called and event details
            g_logger.log(LogLevel::VERBOSE, DEBUG_ARGS, msg);
            break;
        default: {
            g_logger.log(LogLevel::WARNING, DEBUG_ARGS, "DEFAULT (should not happen!): ", g_eventTypeToStrMap.at(msg->event_type));
            g_logger.log(LogLevel::VERBOSE, DEBUG_ARGS, msg);
            return ret;
        }
    }

    g_logger.log(LogLevel::INFO, DEBUG_ARGS, composeDebugMessage());
    return ret;
}

std::vector<std::string> CloudProvider::FilterCloudFolders(const std::vector<std::string> &eventPaths) const
{
    std::vector<std::string> ret;
    for (const auto &eventPath : eventPaths)
        for (const auto &cpPath : paths)
            if (eventPath.find(cpPath) != std::string::npos)
                ret.push_back(eventPath);
    return ret;
}

// MARK: - Protected
// MARK: Callbacks
/// Allows reading to everybody if in RONLY mode,
/// otherwise blocks everything except whitelisted apps
es_auth_result_t CloudProvider::AuthReadGeneral(const std::string &bundleId) const
{
    es_auth_result_t ret = ES_AUTH_RESULT_ALLOW;

    // ALLOW the operation if not in FULL blocking mode
    if (bl != BlockLevel::FULL)
        return ret;

    // Otherwise block everything except whitelisted apps
    if (!BundleIdIsAllowed(bundleId))
        ret = ES_AUTH_RESULT_DENY;

    return ret;
}

/// Blocks all operations except whitelisted apps, and
/// allows  content modifying operations  by dropbox in dropbox cache folders.
es_auth_result_t CloudProvider::AuthWriteGeneral(const std::string &bundleId, const std::vector<std::string> &cpPaths, const es_message_t * const msg) const
{
    es_auth_result_t ret = ES_AUTH_RESULT_ALLOW;

    if (BundleIdIsAllowed(bundleId))
        return ret;

    // If there is any restriction block the operation.
    if (bl != BlockLevel::NONE)
        ret = ES_AUTH_RESULT_DENY;

    // But in case of CLONE operation...check the direction of the operation.
    if (bl == BlockLevel::RONLY && msg->event_type == ES_EVENT_TYPE_AUTH_CLONE) {
        // If it's not cloning within the cloud check the direction.
        if (cpPaths.size() == 1
            && cpPaths[0] == to_string(msg->event.clone.source->path)) {
            // In RONLY mode, we are interested if it the destination is outside of the cloud so we should not block it.
            ret = ES_AUTH_RESULT_ALLOW;
        }
        else {
            // Otherwise it's being cloned into the cloud. Block it
            ret = ES_AUTH_RESULT_DENY;
        }
    }

    // The app is not whitelisted and there is no restriction.
    return ret;
}

uint32_t CloudProvider::AuthOpen(const std::string &bundleId, const std::vector<std::string> &cpPaths, const uint32_t fflags) const
{
    if (cpPaths.size() != 1)
        throw "Open called with wrong paths!";

    uint32_t ret = fflags;
    if (BundleIdIsAllowed(bundleId))
        return ret;

    // If any restriction is set
    if (bl != BlockLevel::NONE) {
        uint32_t mask = ~0;

        if (bl == BlockLevel::RONLY)
            mask = ~(FWRITE | FAPPEND | O_CREAT | O_TRUNC);
        else
            mask = 0;

        ret = fflags & mask;
    }

    return ret;
}
