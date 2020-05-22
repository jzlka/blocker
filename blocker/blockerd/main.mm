//
//  main.mm
//  blockerd
//
//  Created by Jozef on 15/05/2020.
//  Copyright © 2020 Jozef Zuzelka. All rights reserved.
//
// todo:     es_mute_path_literal(endpointClient, [NSProcessInfo.processInfo.arguments[0] UTF8String]);
// Source: https://gist.github.com/Omar-Ikram/8e6721d8e83a3da69b31d4c2612a68ba/


#include <atomic>
#include <getopt.h>
#include <iostream>
#include <signal.h>
#include <unordered_map>
#import <Foundation/Foundation.h>

#include "blocker.hpp"
#include "../../Common/logger.hpp"


void signalHandler(int signum)
{
    Blocker &blocker = Blocker::GetInstance();

    blocker.PrintStats();
    blocker.Uninit();

    // Not safe, but whatever
    std::cerr << "Interrupt signal (" << signum << ") received, exiting." << std::endl;
    exit(signum);
}

void printHelp()
{
    std::cout << "Usage: blockerd  [<cloud_provider> <block_level>] [-v <0-4>] [-h]" << std::endl;
    std::cout << "    -v, --verbosity   Verbosity level [0-4]. Default is 3."        << std::endl;
    std::cout << "    -h, --help        Print usage."                                << std::endl;
    std::cout << "Supported Cloud Providers:"                                        << std::endl;
    std::cout << "    -i, --icloud      iCloud"                                      << std::endl;
    std::cout << "    -d, --dropbox     Dropbox"                                     << std::endl;
    std::cout << "Block Levels:"                                                     << std::endl;
    std::cout << "    none              No blocking"                                 << std::endl;
    std::cout << "    ronly             Read-only mode"                              << std::endl;
    std::cout << "    full              Full blocking mode"                          << std::endl;
    std::cout << "Default blocking level is \"none\"."                               << std::endl;
    std::cout << std::endl;
}


static const struct option longopts[] =
{
    { "icloud",      required_argument, nullptr,    'i' },
    { "dropbox",     required_argument, nullptr,    'd' },
    { "verbosity",   required_argument, nullptr,    'v' },
    { "help",        no_argument,       nullptr,    'h' },
    { nullptr,       0,                 nullptr,     0  }
};


bool parseArguments(const int argc, char * const argv[], bool &help, std::unordered_map<CloudProviderId, BlockLevel> &config)
{
    Logger &logger = Logger::getInstance();

    if (argc < 2 || argc > (sizeof(longopts) / sizeof(longopts[0])))
        return false;

    int optionIndex = 0;
    char opt = 0;
    std::string logLevel;
    std::unordered_map<CloudProviderId,std::string> blockLvls;

    while((opt = getopt_long(argc, argv, "i:d:v:h", longopts, &optionIndex)) != -1)
    {
        switch (opt)
        {
            case 0:                                                     break;
            case 'i':   blockLvls[CloudProviderId::ICLOUD]  = optarg;   break;
            case 'd':   blockLvls[CloudProviderId::DROPBOX] = optarg;   break;
            case 'v':   logLevel  = optarg;   break;
            case 'h':   help      = true;     return true;
            default:                          return false;
        }
    }

    if (!logLevel.empty())
        logger.setLogLevel(logLevel);

    for (const auto &[cp,lvl] : blockLvls) {
        BlockLevel cpBlockLvl;
        if (lvl == "none")
            cpBlockLvl = BlockLevel::NONE;
        else if (lvl == "ronly")
            cpBlockLvl = BlockLevel::RONLY;
        else if (lvl == "full")
            cpBlockLvl = BlockLevel::FULL;
        else {
            logger.log(LogLevel::ERR, "Unsupported block level. Setting: \"none\" for ", g_cpToStr.at(cp), ".");
            cpBlockLvl = BlockLevel::NONE;
        }

        config[cp] = cpBlockLvl;
    }

    return true;
}



int main(const int argc, char * const argv[]) {
    // No runloop, no problem
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGABRT, signalHandler);

    const char* demoName = "blockerd";
    std::string demoPath = "/tmp/" + std::string(demoName) + "-demo";

    std::cout << "(" << demoName << ") Hello, World!\n";
    std::cout << "Point of interest: " << demoPath << std::endl << std::endl;

    @autoreleasepool {

        Logger &logger = Logger::getInstance();
        logger.setLogLevel(LogLevel::INFO);

        bool help = false;
        std::unordered_map<CloudProviderId, BlockLevel> config;
        if (!parseArguments(argc, argv, help, config)) {
            printHelp();
            return EXIT_FAILURE;
        }

        if (help) {
            printHelp();
            return EXIT_SUCCESS;
        }

        Blocker &blocker = Blocker::GetInstance();
        for (const auto &[cpId, blkLvl] : config) {
            if (cpId == CloudProviderId::ICLOUD)
                blocker.m_config[cpId] = ICloud(blkLvl, {demoPath});
            else
                panic("");
        }

        if (!blocker.Init())
            return EXIT_FAILURE;

        dispatch_main();
    }

    return EXIT_SUCCESS;
}
