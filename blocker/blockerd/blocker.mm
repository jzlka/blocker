//
//  blocker.cpp
//  blockerd
//
//  Created by Jozef on 19/05/2020.
//  Copyright © 2020 Jozef Zuzelka. All rights reserved.
//

#include <EndpointSecurity/EndpointSecurity.h>
#include "blocker.hpp"


Blocker& Blocker::GetInstance()
{
    static Blocker blocker;
    return blocker;
}

//bool Blocker::Init();
//bool Blocker::Uninit();


void Blocker::IncreaseStats(const BlockerStats type, int count)
{
    std::scoped_lock<std::mutex> lock(m_mtx);
    switch (type)
    {
        case BlockerStats::EVENT_COPY_ERR:
            m_stats.copyErr += count;
            break;
        case BlockerStats::EVENT_DROPPED_KERNEL:
            m_stats.droppedKernel += count;
            break;
        case BlockerStats::EVENT_DROPPED_DEADLINE:
            m_stats.droppedDeadline += count;
            break;
    }
}

void Blocker::HandleEvent(es_client_t * const clt, const es_message_t * const msg)
{
//    // Check seq_num to recognize dropped events
//    static int lastSeq = msg->
//    //std::cout << msg << std::endl;
//
//     // Handle subscribed AUTH events:
//     if (msg->action_type == ES_ACTION_TYPE_AUTH) {
//         es_respond_result_t res;
//
//         if (msg->event_type == ES_EVENT_TYPE_AUTH_OPEN) {
//             res = es_respond_flags_result(clt, msg, flags_event_handler(msg), false);
//         } else {
//             res = es_respond_auth_result(clt, msg, auth_event_handler(msg), false);
//         }
//
//         if (res != ES_RESPOND_RESULT_SUCCESS)
//             std::cerr << "es_respond_auth_result: " << g_respondResultToStrMap.at(res) << std::endl;
//     } else {
//         notify_event_handler(msg);
//     }
//
//    static const auto find_occurence = [](const std::string& str) {
//        for (const auto &path : g_blockedPaths) {
//            if (str.find(path) != std::string::npos) {
//                std::cout << "*** Occurence found: " << str << std::endl;
//                return true;
//            }
//        }
//        return false;
//    };
}

