//
//  base.cpp
//  blockerd
//
//  Created by Jozef on 05/06/2020.
//  Copyright © 2020 Jozef Zuzelka. All rights reserved.
//

#include <any>

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

bool CloudProvider::BundleIdIsAllowed(const es_string_token_t bundleId) const
{
    return (std::find(allowedBundleIds.begin(), allowedBundleIds.end(), to_string(bundleId)) != allowedBundleIds.end());
}

std::any CloudProvider::HandleEvent(const es_message_t * const msg) const
{
    std::any ret = getDefaultESResponse(msg);
    const std::vector<const std::string> eventPaths = paths_from_event(msg);

    const auto composeDebugMessage = [&]() {
        std::string msgToPrint = "(" + g_blockLvlToStr.at(bl) + ") ";
        msgToPrint += g_eventTypeToStrMap.at(msg->event_type) + " - ";
        if (ret.type() == typeid(es_auth_result_t)) {
            msgToPrint += (std::any_cast<es_auth_result_t>(ret) == ES_AUTH_RESULT_DENY ? (RED "BLOCKING" CLR) : (GRN "ALLOWING" CLR));
        } else if (ret.type() == typeid(uint32_t)) {
            char *allowedFlags = esfflagstostr(std::any_cast<uint32_t>(ret));
            char *blockedFlags = esfflagstostr(std::any_cast<uint32_t>(ret) ^ msg->event.open.fflag);

            msgToPrint += ("ALLOWING (" GRN);
            msgToPrint += (allowedFlags == nullptr ? "null" : allowedFlags);
            msgToPrint += (CLR "), BLOCKING (" RED);
            msgToPrint += (blockedFlags == nullptr ? "null" : blockedFlags);
            msgToPrint += (CLR ")");

            free(allowedFlags);     allowedFlags = nullptr;
            free(blockedFlags);     blockedFlags = nullptr;
        }

        msgToPrint += " operation at";
        for (const auto &path : eventPaths)
            msgToPrint += " '" + path + "'";

        msgToPrint += " by " + to_string(msg->process->signing_id);
        return msgToPrint;
    };

    // Bundle is allowed, lets do it its job.
    if (BundleIdIsAllowed(msg->process->signing_id)) {
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
            g_logger.log(LogLevel::VERBOSE, DEBUG_ARGS, msg);
        case ES_EVENT_TYPE_NOTIFY_ACCESS:
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            break;
            // MARK: AUTH
        case ES_EVENT_TYPE_AUTH_OPEN:
            ret = AuthOpen(msg);
            break;
        case ES_EVENT_TYPE_AUTH_MOUNT:
            g_logger.log(LogLevel::VERBOSE, DEBUG_ARGS, msg);
            break;
        case ES_EVENT_TYPE_AUTH_READDIR:
            ret = AuthReaddir(msg);
            break;
        case ES_EVENT_TYPE_AUTH_RENAME:
            ret = AuthRename(msg);
            break;
        case ES_EVENT_TYPE_AUTH_CREATE:
            ret = AuthCreate(msg);
            break;
        case ES_EVENT_TYPE_AUTH_CLONE: // TODO: check when it's called for proper blocking
        case ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE: // TODO: check when it's called for proper blocking
        case ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE: // TODO: check when it's called for proper blocking
        case ES_EVENT_TYPE_AUTH_LINK: // TODO: check when it's called for proper blocking
        case ES_EVENT_TYPE_AUTH_READLINK:
        case ES_EVENT_TYPE_AUTH_TRUNCATE: // TODO: check when it's called for proper blocking
        case ES_EVENT_TYPE_AUTH_UNLINK: // TODO: check when it's called for proper blocking
        {
            // These events are content-changing operations so we don't need to check the mode.
            // Just deny the operation if there is any restriction...
            if (bl != BlockLevel::NONE)
                ret = (es_auth_result_t)ES_AUTH_RESULT_DENY;

            g_logger.log(LogLevel::VERBOSE, DEBUG_ARGS, msg);
            break;
        }
        default: {
            g_logger.log(LogLevel::WARNING, DEBUG_ARGS, "DEFAULT (should not happen!): ", g_eventTypeToStrMap.at(msg->event_type));
            g_logger.log(LogLevel::VERBOSE, DEBUG_ARGS, msg);
            return ret;
        }
    }

    g_logger.log(LogLevel::INFO, DEBUG_ARGS, composeDebugMessage());
    return ret;
}

// MARK: - Private
bool CloudProvider::ContainsDropboxCacheFolder(const std::vector<const std::string> &eventPaths) const
{
    for (const auto &dropboxPath : paths) {
        std::string dropboxCache = dropboxPath + "/.dropbox.cache";

        for (const auto &eventPath : eventPaths)
            if (eventPath.find(dropboxCache) != std::string::npos)
                return true;
    }
    return false;
}

// MARK: Callbacks
es_auth_result_t CloudProvider::AuthReaddir(const es_message_t * const msg) const
{
    if (msg->event_type != ES_EVENT_TYPE_AUTH_READDIR)
        throw "Wrong callback called! (readdir)";

    es_auth_result_t ret = ES_AUTH_RESULT_ALLOW;

    // DENY only in FULL blocking mode
    if (bl != BlockLevel::FULL)
        return ret;

    // If the application is not whitelisted DENY it
    if (!BundleIdIsAllowed(msg->process->signing_id))
        ret = ES_AUTH_RESULT_DENY;

    return ret;
}

es_auth_result_t CloudProvider::AuthRename(const es_message_t * const msg) const
{
    if (msg->event_type != ES_EVENT_TYPE_AUTH_RENAME)
        throw "Wrong callback called! (rename)";

    es_auth_result_t ret = ES_AUTH_RESULT_ALLOW;

    if (BundleIdIsAllowed(msg->process->signing_id))
        return ret;

    const std::string dropboxBundleId = "com.getdropbox.dropbox";
    std::string bundleId = to_string(msg->process->signing_id);
    // If the rename is from/to one of Dropbox folders, allow it.
    // !!!: we expect that the Dropbox cache folder is not accesible using Dropbox file explorer (which is true so far) so an user cannot do any mess there using the Dropbox app.
    if (id == CloudProviderId::DROPBOX && bundleId == dropboxBundleId && ContainsDropboxCacheFolder(paths_from_event(msg))) {
        g_logger.log(LogLevel::VERBOSE, DEBUG_ARGS, "Ignoring Dropbox process.\n", msg);
        return ret;
    }

    // If there is any restriction block the operation.
    if (bl != BlockLevel::NONE)
        ret = ES_AUTH_RESULT_DENY;

    // The app is not whitelisted and there is no restriction.
    return ret;
}

es_auth_result_t CloudProvider::AuthCreate(const es_message_t * const msg) const
{
    if (msg->event_type != ES_EVENT_TYPE_AUTH_CREATE)
        throw "Wrong callback called! (create)";

    if (BundleIdIsAllowed(msg->process->signing_id))
        return ES_AUTH_RESULT_ALLOW;

    const std::string dropboxBundleId = "com.getdropbox.dropbox";
    std::string bundleId = to_string(msg->process->signing_id);
    // If the rename is from/to one of Dropbox folders, allow it.
    // !!!: we expect that the Dropbox cache folder is not accesible using Dropbox file explorer (which is true so far) so an user cannot do any mess there using the Dropbox app.
    if (id == CloudProviderId::DROPBOX && bundleId == dropboxBundleId && ContainsDropboxCacheFolder(paths_from_event(msg))) {
        g_logger.log(LogLevel::VERBOSE, DEBUG_ARGS, "Ignoring Dropbox process.\n", msg);
        return ES_AUTH_RESULT_ALLOW;
    }

    // If there is any restriction block the operation.
    if (bl != BlockLevel::NONE)
        return ES_AUTH_RESULT_DENY;

    // The app is not whitelisted and there is no restriction.
    return ES_AUTH_RESULT_ALLOW;
}

uint32_t CloudProvider::AuthOpen(const es_message_t * const msg) const
{
    if (msg->event_type != ES_EVENT_TYPE_AUTH_OPEN)
        throw "Wrong callback called! (open)";

    uint32_t ret = msg->event.open.fflag;
    if (BundleIdIsAllowed(msg->process->signing_id))
        return ret;

    const std::string dropboxBundleId = "com.getdropbox.dropbox";
    std::string bundleId = to_string(msg->process->signing_id);
    // If the rename is from/to one of Dropbox folders, allow it.
    // !!!: we expect that the Dropbox cache folder is not accesible using Dropbox file explorer (which is true so far) so an user cannot do any mess there using the Dropbox app.
    if (id == CloudProviderId::DROPBOX && bundleId == dropboxBundleId && ContainsDropboxCacheFolder(paths_from_event(msg))) {
        g_logger.log(LogLevel::VERBOSE, DEBUG_ARGS, "Ignoring Dropbox process.\n", msg);
        return ret;
    }

    // If any restriction is set
    if (bl != BlockLevel::NONE) {
        uint32_t mask = ~0;

        if (bl == BlockLevel::RONLY)
            mask = ~(FWRITE | FAPPEND | O_CREAT); // TODO: validate these flags
        else
            mask = 0;

        ret = msg->event.open.fflag & mask;
    }

    return ret;
}
