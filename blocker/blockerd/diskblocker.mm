//
//  diskblocker.cpp
//  blockerd
//
//  Created by Jozef on 05/06/2020.
//  Copyright © 2020 Jozef Zuzelka. All rights reserved.
//

#include "diskblocker.hpp"

bool DiskBlocker::Init()
{
    return true;
}


void DiskBlocker::Uninit()
{
}

bool DiskBlocker::Configure()
{
    return true;
}

void DiskBlocker::PrintStats()
{
}

DiskBlocker& DiskBlocker::GetInstance()
{
    static DiskBlocker diskBlocker;
    return diskBlocker;
}
