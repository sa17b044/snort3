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
// knxnetip_util.h author Alija Sabic <sabic@technikum-wien.at>

#ifndef KNXNETIP_UTIL_H
#define KNXNETIP_UTIL_H

#include <arpa/inet.h>
#include <cstdint>
#include <string>
#include "protocols/packet.h"
#include "detection/detection_engine.h"
#include "knxnetip_module.h"
#include "knxnetip_tables.h"

namespace knxnetip
{
    namespace util
    {
        /* Get pointer to data fields */
        template <typename T>
        void get(const T*& d, const uint8_t* p, int& offset, uint16_t payload_length, int length = 0)
        {
            if ((payload_length != 0) and
                (payload_length - offset) < (length ? sizeof(T) : length))
            {
                /*FIXME: alert */
                DetectionEngine::queue_event(GID_KNXNETIP, KNXNETIP_DUMMY);
            } else {

                d = reinterpret_cast<const T*>(p + offset);

                if (length == 0)
                    offset += sizeof(T);
                else
                    offset += length;
            }
        }

        /* Load enumeration value */
        template <typename E>
        auto val(E const v) -> typename std::underlying_type<E>::type
        {
            return static_cast<typename std::underlying_type<E>::type>(v);
        }

    }

}

#endif /* KNXNETIP_UTIL_H */
