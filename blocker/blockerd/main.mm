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
#include <iostream>
#include <signal.h>
#import <Foundation/Foundation.h>

#include "blocker.hpp"


std::atomic<bool> g_shouldStop = false;

void signalHandler(int signum)
{
    g_shouldStop = true;

    Blocker &blocker = Blocker::GetInstance();

    blocker.PrintStats();
    blocker.Uninit();

    // Not safe, but whatever
    std::cerr << "Interrupt signal (" << signum << ") received, exiting." << std::endl;
    exit(signum);
}

int main() {
    // No runloop, no problem
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGABRT, signalHandler);

    const char* demoName = "blockerd";
    std::string demoPath = "/tmp/" + std::string(demoName) + "-demo";

    std::cout << "(" << demoName << ") Hello, World!\n";
    std::cout << "Point of interest: " << demoPath << std::endl << std::endl;


    @autoreleasepool {
        Blocker &blocker = Blocker::GetInstance();
        blocker.m_config[CloudProviderId::ICLOUD] = ICloud(BlockLevel::RONLY, {demoPath});

        if (!blocker.Init())
            return EXIT_FAILURE;

        dispatch_main();
    }

    return EXIT_SUCCESS;
}
