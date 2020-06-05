//
//  blocker.hpp
//  blockerd
//
//  Created by Jozef on 19/05/2020.
//  Copyright © 2020 Jozef Zuzelka. All rights reserved.
//

#ifndef blocker_hpp
#define blocker_hpp

#include <any>
#include <cstdint>
#include <EndpointSecurity/EndpointSecurity.h>
#include <functional>
#include <unordered_map>
#include <mutex>
#include <string>
#include <vector>

#include "Clouds/base.hpp"
#include "cloudblocker.hpp"
#include "diskblocker.hpp"

extern const std::unordered_map<BlockLevel, const std::string> g_blockLvlToStr;



class Blocker
{
    CloudBlocker &cloudBlocker = CloudBlocker::GetInstance();
    DiskBlocker &diskBlocker = DiskBlocker::GetInstance();

public:

    Blocker() = default;
    ~Blocker() = default;
    // delete copy operations
    Blocker(const Blocker &) = delete;
    void operator=(const Blocker &) = delete;

    static Blocker& GetInstance();
    bool Init();
    void Uninit();
    bool Configure(const std::unordered_map<CloudProviderId, BlockLevel> &config);

    // MARK: Logging
    void PrintStats();
};

#endif /* blocker_hpp */
