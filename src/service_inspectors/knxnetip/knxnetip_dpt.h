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
// knxnetip_dpt.h author Alija Sabic <sabic@technikum-wien.at>

#ifndef KNXNETIP_DPT_H
#define KNXNETIP_DPT_H

#include <string>
#include "knxnetip_apdu.h"
#include "knxnetip_module.h"

namespace knxnetip
{

    namespace dpt
    {
        enum class Type : uint32_t
        {
            DPT_SWITCH                  = 0x00010001,
            DPT_BOOL                    = 0x00010002,
            DPT_ENABLE                  = 0x00010003,
            DPT_RAMP                    = 0x00010004,
            DPT_ALARM                   = 0x00010005,
            DPT_BINARYVALUE             = 0x00010006,
            DPT_STEP                    = 0x00010007,
            DPT_UPDOWN                  = 0x00010008,
            DPT_OPENCLOSE               = 0x00010009,
            DPT_START                   = 0x0001000a,
            DPT_STATE                   = 0x0001000b,
            DPT_INVERT                  = 0x0001000c,
            DPT_DIMSENDSTYLE            = 0x0001000d,
            DPT_INPUTSOURCE             = 0x0001000e,
            DPT_RESET                   = 0x0001000f,
            DPT_ACK                     = 0x00010010,
            DPT_TRIGGER                 = 0x00010011,
            DPT_OCCUPANCY               = 0x00010012,
            DPT_WINDOW_DOOR             = 0x00010013,
            DPT_LOGICAL_FUNCTION        = 0x00010015,
            DPT_SCENE_AB                = 0x00010016,
            DPT_SHUTTER_BLINDS_MODE     = 0x00010017,
            DPT_HEAT_COOL               = 0x00010064,
            DPT_SWITCH_CONTROL          = 0x00020001,
            DPT_BOOL_CONTROL            = 0x00020002,
            DPT_ENABLE_CONTROL          = 0x00020003,
            DPT_RAMP_CONTROL            = 0x00020004,
            DPT_ALARM_CONTROL           = 0x00020005,
            DPT_BINARY_CONTROL          = 0x00020006,
            DPT_STEP_CONTROL            = 0x00020007,
            DPT_UPDOWN_CONTROL          = 0x00020008,
            DPT_OPENCLOSE_CONTROL       = 0x00020009,
            DPT_START_CONTROL           = 0x0002000a,
            DPT_STATE_CONTROL           = 0x0002000b,
            DPT_INVERT_CONTROL          = 0x0002000c,
            DPT_CONTROL_DIMMING         = 0x00030007,
            DPT_CONTROL_BLINDS          = 0x00030008,
            DPT_TEMPERATURE             = 0x00090001,
            DPT_TEMPERATURE_DIFFERENCE  = 0x00090002,
            DPT_TEMPERATURE_GRADIENT    = 0x00090003,
            DPT_INTENSITY_OF_LIGHT      = 0x00090004,
            DPT_WIND_SPEED              = 0x00090005,
            DPT_AIR_PRESSURE            = 0x00090006,
            DPT_HUMIDITY                = 0x00090007,
            DPT_AIRQUALITY              = 0x00090008,
            DPT_AIR_FLOW                = 0x00090009,
            DPT_TIME_DIFFERENCE         = 0x0009000a,
            DPT_TIME_DIFFERENCE2        = 0x0009000b,
            DPT_VOLTAGE                 = 0x00090014,
            DPT_ELECTRICAL_CURRENT      = 0x00090015,
            DPT_POWERDENSITY            = 0x00090016,
            DPT_KELVIN_PER_PERCENT      = 0x00090017,
            DPT_POWER                   = 0x00090018,
            DPT_VOLUME_FLOW             = 0x00090019,
            DPT_RAIN_AMOUNT             = 0x0009001a,
            DPT_TEMP_F                  = 0x0009001b,
            DPT_WIND_SPEED_KMH          = 0x0009001c
        };

        struct DPT
        {
            std::string id;
            std::string desc;
            std::string lower;
            std::string upper;
            std::string unit;

            DPT() {}
            DPT(std::string id, std::string description, std::string lower, std::string upper) :
                id{id}, desc{description}, lower{lower}, upper{upper} {}
            DPT(std::string id, std::string description, std::string lower, std::string upper, std::string unit) :
                id{id}, desc{description}, lower{lower}, upper{upper}, unit{unit} {}
        };

        struct DPTXlator
        {
            DPT type {};

            void set_type(uint32_t id);
        };

        class DPTXlatorBoolean : public DPTXlator
        {
            const uint8_t* data;
        public:
            DPTXlatorBoolean(uint32_t id, const uint8_t* data);
            std::string get_value();
        };

        class DPTXlator1BitControlled : public DPTXlator
        {
            const uint8_t* data;
        public:
            DPTXlator1BitControlled(uint32_t id, const uint8_t* data);
            std::string get_value();
        };

        class DPTXlator3BitControlled : public DPTXlator
        {
            const uint8_t* data;
        public:
            DPTXlator3BitControlled(uint32_t id, const uint8_t* data);
            std::string get_value();
        };

        class DPTXlator2ByteFloat : public DPTXlator
        {
            const uint16_t* data;
        public:
            DPTXlator2ByteFloat(uint32_t id, const uint16_t* data);
            std::string get_value();
        };

        using knxnetip::packet::cemi::apdu::GroupValue;
        using knxnetip::module::Spec;
        using knxnetip::module::server;
        using knxnetip::module::policy;
        using snort::Packet;

        bool is_extrema(GroupValue& gv, Spec spec, const Packet& p, server& server, const policy& policy);
//        extern const std::map<knxnetip::dpt::Type, knxnetip::dpt::DPT> map;
    }

}

#endif /* KNXNETIP_DPT_H */
