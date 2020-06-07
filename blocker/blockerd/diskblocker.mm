//
//  diskblocker.cpp
//  blockerd
//
//  Created by Jozef on 05/06/2020.
//  Copyright © 2020 Jozef Zuzelka. All rights reserved.
//

#include <DiskArbitration/DiskArbitration.h>

#include "../../Common/logger.hpp"
#include "diskblocker.hpp"


static Logger &g_logger = Logger::getInstance();

// MARK: DiskBlockerTrampoline
DADissenterRef DiskBlockerTrampoline::Probing(DADiskRef disk, void *context)
{
    if (context == nullptr)
        return NULL;
    return static_cast<DiskBlocker*>(context)->Probing(disk, nullptr);
}


void DiskBlockerTrampoline::DiskAdded(DADiskRef disk, void *context)
{
    if (context == nullptr)
        return;

    return static_cast<DiskBlocker*>(context)->DiskAdded(disk, nullptr);
}

void DiskBlockerTrampoline::DiskRemoved(DADiskRef disk, void *context)
{
    if (context == nullptr)
        return;

    return static_cast<DiskBlocker*>(context)->DiskRemoved(disk, nullptr);
}

void DiskBlockerTrampoline::DiskRenamed(DADiskRef disk, CFArrayRef keys, void *context)
{
    if (context == nullptr)
        return;

    return static_cast<DiskBlocker*>(context)->DiskRenamed(disk, keys, nullptr);
}

// MARK: DiskBlocker
DADissenterRef DiskBlocker::Probing(DADiskRef disk, void *)
{
    int allow = 0;
    if (allow) {
        /* Return NULL to allow */
        std::cerr << "allow_mount: allowing mount >" << (DADiskGetBSDName(disk) ? DADiskGetBSDName(disk) : "") << "<." << std::endl;
        m_stats.allowedDisks++;
        return NULL;
    } else {
        /* Return a dissenter to deny */
        std::cerr << "allow_mount: refusing mount >" << (DADiskGetBSDName(disk) ? DADiskGetBSDName(disk) : "") << "<." << std::endl;
        m_stats.blockedDisks++;
        return DADissenterCreate(
                                 kCFAllocatorDefault,
                                 kDAReturnExclusiveAccess,
                                 CFSTR("USB Not Allowed To Mount!"));
    }
}

void DiskBlocker::DiskAdded(DADiskRef disk, void *)
{
    g_logger.log(LogLevel::INFO, DEBUG_ARGS, "New disk appeared >", (DADiskGetBSDName(disk) ? DADiskGetBSDName(disk) : ""), "<.");
    m_stats.connectedDisks++;
}

void DiskBlocker::DiskRemoved(DADiskRef disk, void *)
{
    g_logger.log(LogLevel::INFO, DEBUG_ARGS, "Disk removed: >", (DADiskGetBSDName(disk) ? DADiskGetBSDName(disk) : ""), "<.");
    m_stats.renamedDisks++;
}

void DiskBlocker::DiskRenamed(DADiskRef disk, CFArrayRef keys, void *)
{
    CFDictionaryRef dict = DADiskCopyDescription(disk);
    CFURLRef fspath = (CFURLRef)CFDictionaryGetValue(dict, kDADiskDescriptionVolumePathKey);

    char buf[MAXPATHLEN];
    if (CFURLGetFileSystemRepresentation(fspath, false, (UInt8 *)buf, sizeof(buf))) {
        std::cout << "Disk " << DADiskGetBSDName(disk) << " is now at " << buf << "\nChanged keys:" << std::endl;
        CFShow(keys);
    } else {
        /* Something is *really* wrong. */
    }
    m_stats.renamedDisks++;
}


// MARK: Public
bool DiskBlocker::Init()
{
    m_session = DASessionCreate(kCFAllocatorDefault);

    // Watch only USB devices
    CFMutableDictionaryRef matchingDict = CFDictionaryCreateMutable(
            kCFAllocatorDefault,
            0,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks);

    CFDictionaryAddValue(matchingDict, kDADiskDescriptionVolumeMountableKey, kCFBooleanTrue);
    //CFDictionaryAddValue(matchingDict, kDADiskDescriptionVolumeNetworkKey, kCFBooleanFalse);

    void *context = this;
    DARegisterDiskAppearedCallback(m_session,
                                   kDADiskDescriptionMatchVolumeMountable,
                                   DiskBlockerTrampoline::DiskAdded,
                                   context);

    /* No context needed here. */
    DARegisterDiskDisappearedCallback(m_session,
                                      matchingDict,
                                      DiskBlockerTrampoline::DiskRemoved,
                                      context);

    CFMutableArrayRef keys = CFArrayCreateMutable(kCFAllocatorDefault, 0, NULL);
    CFArrayAppendValue(keys, kDADiskDescriptionVolumeNameKey);

    DARegisterDiskDescriptionChangedCallback(m_session,
                                             matchingDict,
                                             keys, /* match the keys specified above */
                                             DiskBlockerTrampoline::DiskRenamed,
                                             context);

    DARegisterDiskMountApprovalCallback(m_session,
                                        matchingDict,
                                        DiskBlockerTrampoline::Probing,
                                        context);


    /* Schedule a disk arbitration session. */
    DASessionScheduleWithRunLoop(m_session, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);

    CFRelease(matchingDict);
    return true;
}


void DiskBlocker::Uninit()
{
    void *context = this;
    DAUnregisterApprovalCallback(m_session, (void *)DiskBlockerTrampoline::Probing, context);
    DAUnregisterCallback(m_session, (void *)DiskBlockerTrampoline::DiskAdded, context);
    DAUnregisterCallback(m_session, (void *)DiskBlockerTrampoline::DiskRemoved, context);
    DAUnregisterCallback(m_session, (void *)DiskBlockerTrampoline::DiskRenamed, context);

    /* Clean up a session. */
    DASessionUnscheduleFromRunLoop(m_session, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    CFRelease(m_session);
}

std::ostream & operator << (std::ostream &out, const DiskBlocker::Stats &stats)
{

    out << "--- DISK BLOCKER STATS ---";
    out << std::endl << "Connected Disks: " << stats.connectedDisks;
    out << std::endl << "Removed Disks: " << stats.removedDisks;
    out << std::endl << "Renamed Disks: " << stats.renamedDisks;
    out << std::endl << "Allowed Disks: " << stats.allowedDisks;
    out << std::endl << "Blocked Disks: " << stats.blockedDisks;
    return out;
}

void DiskBlocker::PrintStats()
{
    std::cout << m_stats << std::endl;
}

DiskBlocker& DiskBlocker::GetInstance()
{
    static DiskBlocker diskBlocker;
    return diskBlocker;
}
