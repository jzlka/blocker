//
//  icloud.cpp
//  blockerd
//
//  Created by Jozef on 05/06/2020.
//

#include "icloud.hpp"

std::vector<std::string> ICloud::FindPaths(const std::string &homePath)
{
    return { homePath + "/Library/Mobile Documents" }; // $HOME/Library/Mobile Documents/com~apple~CloudDocs
}
