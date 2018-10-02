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
// knxnetip_dpt.cc author Alija Sabic <sabic@technikum-wien.at>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "knxnetip_dpt.h"
#include "knxnetip_tables.h"
#include "knxnetip_detect.h"

#include <iomanip>
#include <sstream>

using knxnetip::dpt::Type;
using knxnetip::dpt::DPT;

//const std::map<Type, DPT> knxnetip::dpt::map
const std::map<Type, DPT> map
{
    { Type::DPT_SWITCH,                 { "1.001", "Switch",                    "off",                  "on",                           "" } },
    { Type::DPT_BOOL,                   { "1.002", "Boolean",                   "false",                "true",                         "" } },
    { Type::DPT_ENABLE,                 { "1.003", "Enable",                    "disable",              "enable",                       "" } },
    { Type::DPT_RAMP,                   { "1.004", "Ramp",                      "no ramp",              "ramp",                         "" } },
    { Type::DPT_ALARM,                  { "1.005", "Alarm",                     "no alarm",             "alarm",                        "" } },
    { Type::DPT_BINARYVALUE,            { "1.006", "Binary value",              "low",                  "high",                         "" } },
    { Type::DPT_STEP,                   { "1.007", "Step",                      "decrease",             "increase",                     "" } },
    { Type::DPT_UPDOWN,                 { "1.008", "Up/Down",                   "up",                   "down",                         "" } },
    { Type::DPT_OPENCLOSE,              { "1.009", "Open/Close",                "open",                 "close",                        "" } },
    { Type::DPT_START,                  { "1.010", "Start",                     "stop",                 "start",                        "" } },
    { Type::DPT_STATE,                  { "1.011", "State",                     "inactive",             "active",                       "" } },
    { Type::DPT_INVERT,                 { "1.012", "Invert",                    "not inverted",         "inverted",                     "" } },
    { Type::DPT_DIMSENDSTYLE,           { "1.013", "Dim send-style",            "start/stop",           "cyclic",                       "" } },
    { Type::DPT_INPUTSOURCE,            { "1.014", "Input source",              "fixed",                "calculated",                   "" } },
    { Type::DPT_RESET,                  { "1.015", "Reset",                     "no action",            "reset",                        "" } },
    { Type::DPT_ACK,                    { "1.016", "Acknowledge",               "no action",            "acknowledge",                  "" } },
    { Type::DPT_TRIGGER,                { "1.017", "Trigger",                   "trigger",              "trigger",                      "" } },
    { Type::DPT_OCCUPANCY,              { "1.018", "Occupancy",                 "not occupied",         "occupied",                     "" } },
    { Type::DPT_WINDOW_DOOR,            { "1.019", "Window/Door",               "closed",               "open",                         "" } },
    { Type::DPT_LOGICAL_FUNCTION,       { "1.021", "Logical function",          "OR",                   "AND",                          "" } },
    { Type::DPT_SCENE_AB,               { "1.022", "Scene A/B",                 "scene A",              "scene B",                      "" } },
    { Type::DPT_SHUTTER_BLINDS_MODE,    { "1.023", "Shutter/Blinds mode",       "only move up/down",    "move up/down + step-stop",     "" } },
    { Type::DPT_HEAT_COOL,              { "1.100", "Heat/Cool",                 "cooling",              "heating",                      "" } },
    { Type::DPT_SWITCH_CONTROL,         { "2.001", "Switch Controlled",         "off",                  "on",                           "" } },
    { Type::DPT_BOOL_CONTROL,           { "2.002", "Boolean Controlled",        "false",                "true",                         "" } },
    { Type::DPT_ENABLE_CONTROL,         { "2.003", "Enable Controlled",         "disable",              "enable",                       "" } },
    { Type::DPT_RAMP_CONTROL,           { "2.004", "Ramp Controlled",           "no ramp",              "ramp",                         "" } },
    { Type::DPT_ALARM_CONTROL,          { "2.005", "Alarm Controlled",          "no alarm",             "alarm",                        "" } },
    { Type::DPT_BINARY_CONTROL,         { "2.006", "Binary Controlled",         "low",                  "high",                         "" } },
    { Type::DPT_STEP_CONTROL,           { "2.007", "Step Controlled",           "decrease",             "increase",                     "" } },
    { Type::DPT_UPDOWN_CONTROL,         { "2.008", "Up/Down Controlled",        "up",                   "down",                         "" } },
    { Type::DPT_OPENCLOSE_CONTROL,      { "2.009", "Open/Close Controlled",     "open",                 "close",                        "" } },
    { Type::DPT_START_CONTROL,          { "2.010", "Start Controlled",          "stop",                 "start",                        "" } },
    { Type::DPT_STATE_CONTROL,          { "2.011", "State Controlled",          "inactive",             "active",                       "" } },
    { Type::DPT_INVERT_CONTROL,         { "2.012", "Invert Controlled",         "not inverted",         "inverted",                     "" } },
    { Type::DPT_CONTROL_DIMMING,        { "3.007", "Dimming",                   "decrease",             "increase",                     "" } },
    { Type::DPT_CONTROL_BLINDS,         { "3.008", "Up/Down",                   "up",                   "down",                         "" } },
    { Type::DPT_TEMPERATURE,            { "9.001", "Temperature",               "-273",                 "+670760",                      "\u00b0C" } },
    { Type::DPT_TEMPERATURE_DIFFERENCE, { "9.002", "Temperature difference",    "-670760",              "+670760",                      "K" } },
    { Type::DPT_TEMPERATURE_GRADIENT,   { "9.003", "Temperature gradient",      "-670760",              "+670760",                      "K/h" } },
    { Type::DPT_INTENSITY_OF_LIGHT,     { "9.004", "Light intensity",           "0",                    "+670760",                      "lx" } },
    { Type::DPT_WIND_SPEED,             { "9.005", "Wind speed",                "0",                    "+670760",                      "m/s" } },
    { Type::DPT_AIR_PRESSURE,           { "9.006", "Air pressure",              "0",                    "+670760",                      "Pa" } },
    { Type::DPT_HUMIDITY,               { "9.007", "Humidity",                  "0",                    "+670760",                      "%%" } },
    { Type::DPT_AIRQUALITY,             { "9.008", "Air quality",               "0",                    "+670760",                      "ppm" } },
    { Type::DPT_AIR_FLOW,               { "9.009", "Air flow",                  "-670760",              "+670760",                      "m\u00b3/h" } },
    { Type::DPT_TIME_DIFFERENCE,        { "9.010", "Time difference 1",         "-670760",              "+670760",                      "s" } },
    { Type::DPT_TIME_DIFFERENCE2,       { "9.011", "Time difference 2",         "-670760",              "+670760",                      "ms" } },
    { Type::DPT_VOLTAGE,                { "9.020", "Voltage",                   "-670760",              "+670760",                      "mV" } },
    { Type::DPT_ELECTRICAL_CURRENT,     { "9.021", "Electrical current",        "-670760",              "+670760",                      "mA" } },
    { Type::DPT_POWERDENSITY,           { "9.022", "Power density",             "-670760",              "+670760",                      "W/m\u00b2" } },
    { Type::DPT_KELVIN_PER_PERCENT,     { "9.023", "Kelvin/percent",            "-670760",              "+670760",                      "K/%%" } },
    { Type::DPT_POWER,                  { "9.024", "Power",                     "-670760",              "+670760",                      "kW" } },
    { Type::DPT_VOLUME_FLOW,            { "9.025", "Volume flow",               "-670760",              "+670760",                      "l/h" } },
    { Type::DPT_RAIN_AMOUNT,            { "9.026", "Rain amount",               "-671088.64",           "670760.96",                    "l/m\u00b2" } },
    { Type::DPT_TEMP_F,                 { "9.027", "Temperature",               "-459.6",               "670760.96",                    "\u00b0F" } },
    { Type::DPT_WIND_SPEED,             { "9.028", "Wind speed",                "0",                    "670760.96",                    "km/h" } }
};



void knxnetip::dpt::DPTXlator::set_type(uint32_t id)
{
    Type t = static_cast<Type>(id);
    if (map.find(t) != map.end()){
        type = map.find(t)->second;
    }
}

knxnetip::dpt::DPTXlatorBoolean::DPTXlatorBoolean(uint32_t id, const uint8_t* data)
{
    set_type(id);
    this->data = data;
}

std::string knxnetip::dpt::DPTXlatorBoolean::get_value()
{
    return (*data) & 0x01 ? type.lower : type.upper;
}

knxnetip::dpt::DPTXlator1BitControlled::DPTXlator1BitControlled(uint32_t id, const uint8_t* data)
{
    set_type(id);
    this->data = data;
}

std::string knxnetip::dpt::DPTXlator1BitControlled::get_value()
{
    std::stringstream ss;

    ss << ((*data) & 0x02) ? "1 " : "0 ";
    ss << ((*data) & 0x01) ? type.lower : type.upper;

    return ss.str();
}

knxnetip::dpt::DPTXlator3BitControlled::DPTXlator3BitControlled(uint32_t id, const uint8_t* data)
{
    set_type(id);
    this->data = data;
}

std::string knxnetip::dpt::DPTXlator3BitControlled::get_value()
{
    std::stringstream ss;
    int steps = (*data) & 0x7;

    ss << ((*data) & 0x8) ? type.lower : type.upper;
    ss << " ";
    
    if (!steps)
        ss << "break";
    else
        ss << steps << " steps";

    return ss.str();
}

knxnetip::dpt::DPTXlator2ByteFloat::DPTXlator2ByteFloat(uint32_t id, const uint16_t* data)
{
    set_type(id);
    this->data = data;
}

// DPT 2 Byte Float= (0.01 * m) * 2^e
static double get_2bytefloat(uint16_t v)
{
    // DPT Format: MEEEMMMM MMMMMMMMM
    // left align mantissa
    int m = ((v & 0x8000) << 16) | ((v & 0x7ff) << 20);
    // normalize
    m >>= 20;

    int exp = (v & 0x7800) >> 11;

    return (1 << exp) * m * 0.01;
}


std::string knxnetip::dpt::DPTXlator2ByteFloat::get_value()
{
    uint16_t v = ntohs(*data);
    double d = get_2bytefloat(v);

    std::stringstream ss;
    ss << d;

    return ss.str();
}


/* FIXME-BE: max, value only work for DPT 9 classes. */
bool knxnetip::dpt::is_extrema(knxnetip::packet::cemi::apdu::GroupValue& gv, knxnetip::module::Spec spec, const snort::Packet& p, knxnetip::module::server& server, const knxnetip::module::policy& policy)
{
    using knxnetip::detection::get_rule_string;
    using snort::TextLog_Flush;
    using snort::TextLog_Print;

    bool result = false;
    uint8_t main = (spec.dpt & 0xffff0000) >> 16;

    std::string unit{}, value{}, extrema{}, rulestring{};
    unsigned sid;

    /* DPT 1.+++ */
    if (main == 1) { }
    /* DPT 2.+++ */
    else if (main == 2) { }
    /* DPT 3.+++ */
    else if (main == 3) { }
    /* DPT 4.+++ */
    else if (main == 4) { }
    /* DPT 5.+++ */
    else if (main == 5) { }
    /* DPT 6.+++ */
    else if (main == 6) { }
    /* DPT 7.+++ */
    else if (main == 7) { }
    /* DPT 8.+++ */
    else if (main == 8) { }
    /* DPT 9: 2 Byte Float */
    else if (main == 9) {
        knxnetip::dpt::DPTXlator2ByteFloat dptx{spec.dpt, (const uint16_t*)gv.data};
        value = dptx.get_value();
        unit = dptx.type.unit;
        double v = std::stod(value);

        if (spec.get_state(Spec::State::MAX) and v > spec.max)
        {
            result = true;
            sid = KNXNETIP_GRPADDR_MAX;
            rulestring = KNXNETIP_GRPADDR_MAX_STR_PAR;

            std::stringstream ss;
            ss << std::fixed << std::setprecision(2) << spec.max;
            extrema = ss.str();
        }
        else if (spec.get_state(Spec::State::MIN) and v < spec.min)
        {
            result = true;
            sid = KNXNETIP_GRPADDR_MIN;
            rulestring = KNXNETIP_GRPADDR_MIN_STR_PAR;

            std::stringstream ss;
            ss << std::fixed << std::setprecision(2) << spec.min;
            extrema = ss.str();
        }
    }

    if (result)
    {
        knxnetip::queue_det_event(sid, p, server, policy);
        if (server.log_knxnetip)
        {
            std::string rule = get_rule_string(rulestring, server.log_to_file);
            TextLog_Print(server.log, rule.c_str(), GID_KNXNETIP, sid, 0,
                                      value.c_str(), unit.c_str(), extrema.c_str(), unit.c_str());
            TextLog_NewLine(server.log);
            TextLog_Flush(server.log);
        }
    }

    return result;
}
