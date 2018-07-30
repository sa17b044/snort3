//--------------------------------------------------------------------------
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// knxnetip_decode.cc author Alija Sabic <sabic@technikum-wien.at>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "knxnetip_decode.h"
#include "knxnetip_module.h"

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "managers/event_manager.h"
#include "protocols/packet.h"

#include "log/messages.h"

using namespace snort;

bool KNXnetIPDecode(Packet *p)
{
    static int i = 0;

    i++;
    LogMessage("detect %d\n",i);

//    EventManager::call_alerters(0, p, nullptr, nullptr);
    DetectionEngine::queue_event(GID_KNXNETIP, 1);

//    DetectionEngine::queue_event(GID_KNXNETIP, 1);
    return true;
}
