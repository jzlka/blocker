//
//  base.cpp
//  blockerd
//
//  Created by Jozef on 05/06/2020.
//  Copyright © 2020 Jozef Zuzelka. All rights reserved.
//

#include "../../../Common/Tools/Tools-ES.hpp"
#include "../../../Common/logger.hpp"
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
