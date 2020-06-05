//
//  blocker.cpp
//  blockerd
//
//  Created by Jozef on 19/05/2020.
//  Copyright © 2020 Jozef Zuzelka. All rights reserved.
//
// TODO: osetrit vynimky na future a std::any, casty a vlastne vsetky ostatne
// TODO: moze byt nebezpecne ked pridaju novy auth event vracajuci flagy a neosetri sa to v default
// TODO: skontrolovat thread safety

#include <unordered_map>

#include "../../Common/logger.hpp"
#include "blocker.hpp"
#include "Clouds/base.hpp"
#include "cloudblocker.hpp"
#include "diskblocker.hpp"



static Logger &g_logger = Logger::getInstance();


// MARK: - Blocker
const std::unordered_map<BlockLevel, const std::string> g_blockLvlToStr = {
    {BlockLevel::NONE,  "NONE"},
    {BlockLevel::RONLY, "RONLY"},
    {BlockLevel::FULL,  "FULL"},
};

Blocker& Blocker::GetInstance()
{
    static Blocker blocker;
    return blocker;
}

bool Blocker::Init()
{
    if (!cloudBlocker.Init()) {
        g_logger.log(LogLevel::ERR, DEBUG_ARGS, "CloudBlocker init failed.");
        //return false;
    }

    if (!diskBlocker.Init()) {
        g_logger.log(LogLevel::ERR, DEBUG_ARGS, "DiskBlocker init failed.");
        return false;
    }

    return true;
}

void Blocker::Uninit()
{
    cloudBlocker.Uninit();
    diskBlocker.Uninit();
}

bool Blocker::Configure(const std::unordered_map<CloudProviderId, BlockLevel> &config)
{
    if (!cloudBlocker.Configure(config)) {
        g_logger.log(LogLevel::ERR, DEBUG_ARGS, "CloudBlocker config failed.");
        return false;
    }

    return true;
}


void Blocker::PrintStats()
{
    cloudBlocker.PrintStats();
    diskBlocker.PrintStats();
}
