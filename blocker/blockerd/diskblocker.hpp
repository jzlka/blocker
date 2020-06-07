//
//  diskblocker.hpp
//  blockerd
//
//  Created by Jozef on 05/06/2020.
//  Copyright © 2020 Jozef Zuzelka. All rights reserved.
//

#ifndef diskblocker_hpp
#define diskblocker_hpp

#include <DiskArbitration/DiskArbitration.h>

class DiskBlockerTrampoline
{
public:
    static _Nonnull DADissenterRef Probing(_Nonnull DADiskRef disk, void * _Nonnull context);
    static void DiskAdded(_Nonnull DADiskRef disk, void * _Nonnull context);
    static void DiskRemoved(_Nonnull DADiskRef disk, void * _Nonnull context);
    static void DiskRenamed(_Nonnull DADiskRef disk, _Nonnull CFArrayRef keys, void * _Nonnull context);
};


class DiskBlocker
{
    struct Stats {
        uint64_t connectedDisks = 0;
        uint64_t allowedDisks   = 0;
        uint64_t blockedDisks   = 0;
        uint64_t removedDisks   = 0;
        uint64_t renamedDisks   = 0;
    };

    _Nullable DASessionRef m_session = nullptr;
    Stats m_stats;

    friend std::ostream & operator << (std::ostream &out, const DiskBlocker::Stats &stats);

public:
    DiskBlocker() = default;
    ~DiskBlocker() = default;
    // delete copy operations
    DiskBlocker(const DiskBlocker &) = delete;
    void operator=(const DiskBlocker &) = delete;

    static DiskBlocker& GetInstance();
    bool Init();
    void Uninit();
    void PrintStats();

    _Nonnull DADissenterRef Probing(_Nonnull DADiskRef disk, void * _Nullable context);
    void DiskAdded(_Nonnull DADiskRef disk, void * _Nullable context);
    void DiskRemoved(_Nonnull DADiskRef disk, void * _Nullable context);
    void DiskRenamed(_Nonnull DADiskRef disk, _Nonnull CFArrayRef keys, void * _Nullable context);
};

#endif /* diskblocker_hpp */
