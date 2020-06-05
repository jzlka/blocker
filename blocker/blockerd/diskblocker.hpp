//
//  diskblocker.hpp
//  blockerd
//
//  Created by Jozef on 05/06/2020.
//  Copyright © 2020 Jozef Zuzelka. All rights reserved.
//

#ifndef diskblocker_hpp
#define diskblocker_hpp

class DiskBlocker
{
public:
    DiskBlocker() = default;
    ~DiskBlocker() = default;
    // delete copy operations
    DiskBlocker(const DiskBlocker &) = delete;
    void operator=(const DiskBlocker &) = delete;

    static DiskBlocker& GetInstance();
    bool Init();
    void Uninit();
    bool Configure();
    void PrintStats();

};

#endif /* diskblocker_hpp */
