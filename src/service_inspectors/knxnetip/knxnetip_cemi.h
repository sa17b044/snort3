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
// knxnetip_cemi.h author Alija Sabic <sabic@technikum-wien.at>

#ifndef KNXNETIP_CEMI_H
#define KNXNETIP_CEMI_H

#include <arpa/inet.h>
#include <cstdint>
#include "protocols/packet.h"
#include "knxnetip_apdu.h"

namespace knxnetip
{
    namespace packet
    {
        /* Common External Message Interface */
        namespace cemi {

            enum class ErrorCode : uint8_t {
                UNSPECIFIED_ERROR = 0x00,
                OUT_OF_RANGE = 0x01,
                OUT_OF_MAXRANGE = 0x02,
                OUT_OF_MINRANGE = 0x03,
                MEMORY_ERROR = 0x04,
                READ_ONLY = 0x05,
                ILLEGAL_COMMAND = 0x06,
                VOID_DP = 0x07,
                TYPE_CONFLICT = 0x08,
                PROP_INDEX_RANGE_ERROR = 0x09,
                VALUE_NOT_WRITEABLE_NOW = 0x0a
            };

            enum class MessageCode : uint8_t {
                L_RAW_REQ = 0x10,
                L_DATA_REQ = 0x11,
                L_POLL_DATA_REQ = 0x13,
                L_POLL_DATA_CON = 0x25,
                L_DATA_IND = 0x29,
                L_BUSMON_IND = 0x2B,
                L_RAW_IND = 0x2D,
                L_DATA_CON = 0x2E,
                L_RAW_CON = 0x2F,
                T_DATA_CONNEC_REQ = 0x41,
                T_DATA_INDV_REQ = 0x4A,
                T_DATA_CONNEC_IND = 0x89,
                T_DATA_INDV_IND = 0x94,
                M_RESET_IND = 0xF0,
                M_RESET_REQ = 0xF1,
                M_PROPWRITE_CON = 0xF5,
                M_PROPWRITE_REQ = 0xF6,
                M_PROPINFO_IND = 0xF7,
                M_FUNCPROPCOM_REQ = 0xF8,
                M_FUNCPROPSTATREAD_REQ = 0xF9,
                M_FUNCPROPCOM_CON = 0xFA,
                M_PROPREAD_CON = 0xFB,
                M_PROPREAD_REQ = 0xFC

            };

            namespace add_info {

                enum class TypeId : uint8_t {
                    RESERVED = 0x00,
                    PL_INFO = 0x01,
                    RF_INFO = 0x02,
                    BUSMON_INFO = 0x03,
                    TIME_REL = 0x04,
                    TIME_DELAY = 0x05,
                    EXEND_TIME = 0x06,
                    BIBAT_INFO = 0x07,
                    RF_MULTI = 0x08,
                    PREAMBEL = 0x09,
                    RF_FAST_ACK = 0x0a,
                    MANU_DATA = 0xfe,
                    RESERVED2 = 0xff
                };

                class PlMediumInfo
                {
                    const uint16_t* domain_address;

                public:
                    void load(const snort::Packet& p, int& offset);

                    uint16_t get_domain_address() const { return ntohs(*domain_address); }
                };

                class RfMediumInfo
                {
                    const uint8_t* rf_info;
                    const uint8_t* serial_number; //[6];
                    const uint8_t* dl_frame_number;

                public:
                    constexpr static const uint8_t ser_num_size = 6;

                    void load(const snort::Packet& p, int& offset);

                    uint8_t get_rf_info() const { return *rf_info; }
                    uint16_t get_serial_number(int i) const { return i >= ser_num_size ? 0 : serial_number[i]; }

                };

                class BusmonitorStatusInfo
                {
                    const uint8_t* error_flags;

                public:
                    void load(const snort::Packet& p, int& offset);

                    uint8_t get_error_flags() const { return *error_flags; }
                };

                class TimestampRelative
                {
                    const uint16_t* timestamp_rel;

                public:
                    void load(const snort::Packet& p, int& offset);

                    uint16_t get_timestamp_rel() const { return ntohs(*timestamp_rel); }
                };

                class TimeDelayUntilSending
                {
                    const uint32_t *time_delay;

                public:
                    void load(const snort::Packet& p, int& offset);

                    uint32_t get_time_delay() const { return ntohl(*time_delay); }
                };

                class ExtendedRelativeTimestamp
                {
                    const uint32_t* timestamp_dev_ind;

                public:
                    void load(const snort::Packet& p, int& offset);

                    uint32_t get_timestamp_dev_ind() const { return ntohl(*timestamp_dev_ind); }
                };

                class BiBatInfo
                {
                    const uint8_t* bibat_ctrl;
                    const uint8_t* bibat_block;

                public:
                    enum BibatCtrl : uint8_t
                    {
                        FAST_ACK = 0x01,
                        SYNCHRONOUS_LDATA = 0x04,
                        SYNC_FRAME = 0x05,
                        HELP_CALL = 0x06,
                        HELP_CALL_RESPONSE = 0x07
                    };

                    void load(const snort::Packet& p, int& offset);

                    BibatCtrl get_bibat_ctrl() const { return static_cast<BibatCtrl>((*bibat_ctrl) >> 4); }
                    uint8_t get_bibat_block() const { return *bibat_block; }
                };

                class RfMultiInfo
                {
                    const uint8_t* transmission_frequency;
                    const uint8_t* call_channel;
                    const uint8_t* fast_ack;
                    const uint8_t* reception_frequency;

                public:
                    void load(const snort::Packet&, int& offset);

                    uint8_t get_transmission_frequency() const { return *transmission_frequency; }
                    uint8_t get_call_channel() const { return *call_channel; }
                    uint8_t get_fast_ack() const { return *fast_ack; }
                    uint8_t get_reception_frequency() const { return *reception_frequency; }
                };

                class PrePostamble
                {
                    const uint16_t* preamble_length;
                    const uint8_t* postamble_length;

                public:
                    void load(const snort::Packet& p, int& offset);

                    uint16_t get_preamble_length() const { return ntohs(*preamble_length); }
                    uint8_t get_postamble_length() const { return *postamble_length; }

                };

                class RfFastAckInfo
                {
                    const uint8_t* status;
                    const uint8_t* info;

                public:
                    uint8_t size;

                    void load(const snort::Packet& p, int& offset, uint8_t length);

                    uint8_t get_status(int i) const { return i >= size ? 0 : *(status + (i*2)); }
                    uint8_t get_info(int i) const { return i >= size ? 0 : *(info + (i*2)); }
                };

                class ManufacturerSpecificData
                {
                    const uint16_t* manufacturer_id;
                    const uint8_t* subfunction;
                    const uint8_t* data;

                public:
                    uint8_t size;
                    void load(const snort::Packet& p, int& offset, uint8_t length);

                    uint16_t get_manufacturer_id() const { return *manufacturer_id; }
                    uint8_t get_subfunction() const { return *subfunction; }
                    uint8_t get_data(int i) const { return i >= size ? 0 : *(data + i); }
                };

            }

            /* FIXME: Add check of add. info. length at end of load */
            class AdditionalInformation
            {
                const uint8_t* type_id;
                const uint8_t* length;

            public:
                union
                {
                    add_info::PlMediumInfo pl_medium_info;
                    add_info::RfMediumInfo rf_medium_info;
                    add_info::BusmonitorStatusInfo bus_monitor_status_info;
                    add_info::TimestampRelative timestamp_relative;
                    add_info::TimeDelayUntilSending time_delay_until_send;
                    add_info::ExtendedRelativeTimestamp extended_relative_timestamp;
                    add_info::BiBatInfo bibat_info;
                    add_info::RfMediumInfo rf_mulfi_info;
                    add_info::PrePostamble pre_postamble;
                    add_info::RfFastAckInfo rf_fastack_info;
                    add_info::ManufacturerSpecificData manufacturer_data;
                };
                void load(const snort::Packet& p, int& offset);

                add_info::TypeId get_type_id() const { return static_cast<add_info::TypeId>(*type_id); }
                uint8_t get_length() const { return *length; }
            };

            /* Interface Object Type */
            namespace iot {

                enum class InterfaceObjectType : uint16_t {
                    /* System Interface Objects */
                    DEVICE_OBJECT = 0x0000, /* Device Object */
                    ADDRESSTABLE_OBJECT = 0x0001, /* Addresstable Object */
                    ASSOCIATIONTABLE_OBJECT = 0x0002, /* Associationtable Object */
                    APPLICATIONPROGRAM_OBJECT = 0x0003, /* Applicationprogram Object */
                    INTERFACEPROGRAM_OBJECT = 0x0004, /* Interfaceprogram Object */
                    KNX_OBJECT_ASSOCIATIONTABLE_OBJECT = 0x0005, /* KNX-Object Associationtable Object */
                    ROUTER_OBJECT = 0x0006, /* Router Object */
                    LTE_ADDRESS_ROUTING_TABLE_OBJECT = 0x0007, /* LTE Address Routing Table Object */
                    C_EMI_SERVER_OBJECT = 0x0008, /* cEMI Server Object */
                    GROUP_OBJECT_TABLE_OBJECT = 0x0009, /* Group Object Table Object */
                    POLLING_MASTER = 0x000a, /* Polling Master */
                    KNXNET_IP_PARAMETER_OBJECT = 0x000b, /* KNXnet/IP Parameter Object */
                    RESERVED = 0x000c, /* Reserved. Shall not be used. */
                    FILE_SERVER_OBJECT = 0x000d, /* File Server Object */

                    /* Application Interface Objects */
                    ROOM_SETPOINT_MANAGER_HVAC_MODE_DRIVEN = 0x0064, /* Room Setpoint Manager HVAC-Mode Driven */
                    ROOM_SETPOINT_MANAGER_TEMPERATURE_DRIVEN = 0x0065, /* Room Setpoint Manager Temperature Driven */
                    SETPOINT_MANAGER_AIR_QUALITY = 0x0066, /* Setpoint Manager Air Quality */
                    SETPOINT_MANAGER_RELATIVE_HUMIDITY = 0x0067, /* Setpoint Manager Relative Humidity */
                    PROGRAMTO_HVAC_MODE_CONVERSION = 0x0068, /* Program to HVAC Mode Conversion */
                    HVAC_EMERGENCY_SOURCE = 0x006c, /* HVAC Emergency Source */
                    BUILDING_OCC_MODE_SOURCE = 0x006d, /* Building/Occ-Mode Source */
                    HVAC_MODE_SCHEDULER = 0x006e, /* HVAC Mode Scheduler */
                    DHW_MODE_SCHEDULER = 0x006f, /* DHW Mode Scheduler */
                    DHW_CIRCULATION_PUMP_SCHEDULER = 0x0070, /* DHW Circulation Pump Scheduler */
                    ABSOLUTE_ROOM_TEMPERATURE_SETPOINT_SCHEDULER = 0x0071, /* Absolute Room Temperature Setpoint Scheduler */
                    HVAC_OPTIMISER = 0x0073, /* HVAC Optimiser */
                    FLOW_TEMPERATURE_CONTROLLER = 0x0078, /* Flow Temperature Controller */
                    BURNER_CONTROLLER = 0x0080, /* Burner Controller */
                    BOILER_CONTROLLER = 0x0081, /* Boiler Controller */
                    HEAT_PRODUCER_MANAGER = 0x0088, /* Heat Producer Manager */
                    HEAT_PRODUCER_MANAGERFOR_BST = 0x0089, /* Heat Producer Manager for BST */
                    HPMFOR_BSTIN_BOILERSUB_CASCADE = 0x008a, /* HPM for BST in Boiler sub-cascade */
                    HEAT_FLOW_DEMAND_MANAGER = 0x0090, /* Heat Flow Demand Manager */
                    AUXILIARY_HEAT_DEMAND = 0x0091, /* Auxiliary Heat Demand */
                    AUXILIARY_HEATING_DEMAND_PERCENT = 0x0092, /* Auxiliary Heating Demand Percent */
                    HEATING_DEMAND_TRANSFORMER_ROOM_TEMPERATURE = 0x0097, /* Heating Demand Transformer Room Temperature */
                    HEATING_DEMAND_TRANSFORMERFOR_AIR_HANDLING_UNITS = 0x0098, /* Heating Demand Transformer for Air Handling Units */
                    RADIATOR_HEATING_ENERGY_DEMAND_TRANSFORMER_TU = 0x0099, /* Radiator Heating Energy Demand Transformer TU */
                    AIR_HEATER_ENERGY_DEMAND_TRANSFORMER_TU = 0x009a, /* Air Heater Energy Demand Transformer TU */
                    HEATING_ZONE_CONTROLLER = 0x00a0, /* Heating Zone Controller */
                    HEATING_INDIVIDUAL_ROOM_CONTROLLER = 0x00a7, /* Heating Individual Room Controller */
                    HEATING_DEMAND_TRANSFORMER_ACTUATOR_POSITION = 0x00a9, /* Heating Demand Transformer Actuator Position */
                    HEATING_ROOM_DEMAND_MANAGER = 0x00aa, /* Heating Room Demand Manager */
                    DOMESTIC_HOT_WATER_SETPOINT_MANAGER = 0x00b0, /* Domestic Hot Water Setpoint Manager */
                    DOMESTIC_HOT_WATER_CONTROLLER = 0x00b1, /* Domestic Hot Water Controller */
                    DHW_CIRCULATION_PUMP_CONTROLLER = 0x00b3, /* DHW Circulation Pump Controller */
                    DHW_TEMPERATURE_SENSOR = 0x00b4, /* DHW Temperature Sensor */
                    DHW_USER_SETTINGS = 0x00b5, /* DHW User Settings */
                    SOLAR_DOMESTIC_HOT_WATER_CONTROLLER = 0x00ba, /* Solar Domestic Hot Water Controller */
                    COLLECTOR_TEMPERATURE_SENSOR = 0x00bb, /* Collector Temperature Sensor */
                    CHILLER_CONTROLLER = 0x00c0, /* Chiller Controller */
                    COLD_WATER_PODUCER_MANAGER = 0x00c7, /* Cold Water Poducer Manager */
                    RE_COOLING_CONTROL = 0x00c8, /* Re-Cooling Control */
                    COOLING_FLOW_DEMAND_MANAGER = 0x00d0, /* Cooling Flow Demand Manager */
                    AUXILIARY_COOLING_DEMAND = 0x00d1, /* Auxiliary Cooling Demand */
                    AUXILIARY_COOLING_DEMAND_PERCENT = 0x00d2, /* Auxiliary Cooling Demand Percent */
                    COOLING_DEMAND_TRANSFORMERFOR_AIR_HANDLING_UNITS = 0x00d7, /* Cooling Demand Transformer for Air Handling Units */
                    CHILLED_CEILING_ENERGY_DEMAND_TRANSFORMER_TU = 0x00d8, /* Chilled Ceiling Energy Demand Transformer TU */
                    AIR_COOLER_ENERGY_DEMAND_TRANSFORMER_TU = 0x00d9, /* Air Cooler Energy Demand Transformer TU */
                    COOLING_ZONE_CONTROLLER = 0x00e0, /* Cooling Zone Controller */
                    AIR_HANDLING_UNIT_CONTROLLER = 0x00f0, /* Air Handling Unit Controller */
                    SUPPLY_AIR_TEMPERATURE_CONTROLLER = 0x00f1, /* Supply Air Temperature Controller */
                    VENTILATION_DEMAND_TRANSFORMER_TU = 0x00f8, /* Ventilation Demand Transformer TU */
                    RADIATOR_ROOM_CONTROL_TU = 0x0100, /* Radiator Room Control TU */
                    RADIATORAND_CHILLED_CEILING_ROOM_CONTROL = 0x0101, /* Radiator and Chilled Ceiling Room Control */
                    FANCOIL_CONTROL = 0x0102, /* Fancoil Control */
                    WATER_HEAT_PUMP_CONTROLFOR_RINGWATER = 0x0103, /* Water Heat Pump Control for Ringwater */
                    SPLIT_UNIT_CONTROL = 0x0104, /* Split Unit Control */
                    VAV_CONTROL_DISCHARGE_AIR = 0x0105, /* VAV Control Discharge Air */
                    VAV_CONTROL_EXTRACT_AIR = 0x0106, /* VAV Control Extract Air */
                    HEATINGAND_COOLING_INDIVIDUAL_ROOM_CONTROLLER = 0x0107, /* Heating and Cooling Individual Room Controller */
                    COOLING_DEMAND_TRANSFORMER_ROOM_TEMPERATURE = 0x0108, /* Cooling Demand Transformer Room Temperature */
                    KNXTO_FIL_PILOTE_CONVERTER_KFP = 0x0127, /* KNX to Fil Pilote Converter (KFP) */
                    OUTSIDE_TEMPERATURE_SENSOR = 0x0140, /* Outside Temperature Sensor */
                    ROOM_TEMPERATURE_SENSOR = 0x0141, /* Room Temperature Sensor */
                    SUPPLY_AIR_TEMPERATURE_SENSOR = 0x0142, /* Supply Air Temperature Sensor */
                    RETURN_AIR_TEMPERATURE_SENSOR = 0x0143, /* Return Air Temperature Sensor */
                    FLOW_WATER_TEMPERATURE_SENSOR = 0x0144, /* Flow Water Temperature Sensor */
                    RETURN_WATER_TEMPERATURE_SENSOR = 0x0145, /* Return Water Temperature Sensor */
                    CONDENSER_FLOW_WATER_TEMPERATURE_SENSOR = 0x0146, /* Condenser Flow Water Temperature Sensor */
                    CONDENSER_RETURN_WATER_TEMPERATURE_SENSOR = 0x0147, /* Condenser Return Water Temperature Sensor */
                    DISCHARGE_AIR_TEMPERATURE_SENSOR = 0x0148, /* Discharge Air Temperature Sensor */
                    FLOOR_TEMPERATURE_SENSOR = 0x0149, /* Floor Temperature Sensor */
                    OUTSIDE_AQ_SENSOR = 0x014a, /* Outside AQ Sensor */
                    ROOM_AQ_SENSOR = 0x014b, /* Room AQ Sensor */
                    SUPPLY_AQ_SENSOR = 0x014c, /* Supply AQ Sensor */
                    RETURN_AQ_SENSOR = 0x014d, /* Return AQ Sensor */
                    OUTSIDE_RELATIVE_HUMIDITY_SENSOR = 0x0150, /* Outside Relative Humidity Sensor */
                    ROOM_RELATIVE_HUMIDITY_SENSOR = 0x0151, /* Room Relative Humidity Sensor */
                    SUPPLY_AIR_RELATIVE_HUMIDITY_SENSOR = 0x0152, /* Supply Air Relative Humidity Sensor */
                    RETURN_AIR_RELATIVE_HUMIDITY_SENSOR = 0x0153, /* Return Air Relative Humidity Sensor */
                    AIR_CHANGE_OVER_STATUS_SENSOR = 0x0155, /* Air Change Over Status Sensor */
                    WATER_CHANGE_OVER_STATUS_SENSOR = 0x0156, /* Water Change Over Status Sensor */
                    WINDOW_SWITCH = 0x0157, /* Window Switch */
                    DEW_POINT_STATUS_SENSOR = 0x0158, /* Dew Point Status Sensor */
                    PRESENCE_DETECTOR = 0x0159, /* Presence Detector */
                    WIND_SPEED_SENSOR = 0x015b, /* Wind Speed Sensor */
                    SUN_INTENSITY_SENSOR = 0x015c, /* Sun Intensity Sensor */
                    HVAC_VALVE_ACTUATOR = 0x0160, /* HVAC Valve Actuator */
                    COMPRESSOR_INVERTING_VALVE_ACTUATOR = 0x0165, /* Compressor Inverting Valve Actuator */
                    AIR_DAMPER_ACTUATOR = 0x016a, /* Air Damper Actuator */
                    ELECTRICAL_HEATING_ELEMENT_ACTUATOR = 0x0171, /* Electrical Heating Element Actuator */
                    FAN_SPEED_ACTUATOR = 0x0174, /* Fan Speed Actuator */
                    COMPRESSOR_ACTUATOR = 0x0175, /* Compressor Actuator */
                    USER_HVAC_ROOM_SETTINGS = 0x0180, /* User HVAC Room Settings */
                    ROOM_TEMPERATURE_SETPOINT_ABSOLUTE_SETTING = 0x0181, /* Room Temperature Setpoint Absolute Setting */
                    USER_AIR_QUALITY_SETPOINT_SETTING = 0x0183, /* User Air Quality Setpoint Setting */
                    USER_RELATIVE_HUMIDITY_SETPOINT_SETTING = 0x0184, /* User Relative Humidity Setpoint Setting */
                    USER_HVAC_DISPLAY = 0x0186, /* User HVAC Display */
                    USER_PRESENCE_SWITCH = 0x0187, /* User Presence Switch */
                    USER_CHANGE_OVER_SETTINGS = 0x0188, /* User Change Over Settings */
                    USER_FAN_SPEED_SETTING = 0x0189, /* User Fan Speed Setting */
                    USER_ENABLE_ALTERNATIVE_ROOM_TEMPERATURE_SETPOINT = 0x018c, /* User Enable Alternative Room Temperature Setpoint */
                    FB_SCENE_SENSOR = 0x0193, /* FB Scene Sensor */
                    TIMED_SENSOR = 0x0196, /* Timed Sensor */
                    ROOM_LIGHT_SETPOINT = 0x0198, /* Room Light Setpoint */
                    INDOOR_BRIGHTNESS_SENSOR = 0x0199, /* Indoor Brightness Sensor */
                    INDOOR_LUMINANCE_SENSOR = 0x019a, /* Indoor Luminance Sensor */
                    MOTION_DETECTOR = 0x019e, /* Motion Detector */
                    ROOM_LIGHT_CONTROLLER = 0x019f, /* Room Light Controller */
                    LIGHT_SWITCHING_ACTUATOR_BASIC = 0x01a1, /* Light Switching Actuator Basic */
                    DIMMING_ACTUATOR_BASIC = 0x01a2, /* Dimming Actuator Basic */
                    FB_DIMMING_SENSOR_BASIC = 0x01a4, /* FB Dimming Sensor Basic */
                    FB_SWITCHING_SENSOR_BASIC = 0x01a5, /* FB Switching Sensor Basic */
                    FB_SUNBLIND_ACTUATOR_BASIC = 0x0320, /* FB Sunblind Actuator Basic */
                    FB_SUNBLIND_SENSOR_BASIC = 0x0321, /* FB Sunblind Sensor Basic */
                    FB_WIND_SENSOR_FB_WIND_ALARM = 0x0322, /* FB_Wind_Sensor/FB_Wind_Alarm */
                    FB_RAIN_SENSOR_FB_RAIN_ALARM = 0x0323, /* FB_Rain_Sensor/FB_Rain_Alarm */
                    FB_FROST_SENSOR = 0x0324, /* FB_Frost_Sensor */
                    SYSTEM_CLOCK = 0x03e9, /* System Clock */
                    ALARM_SOURCE = 0x03ea, /* AlarmSource */
                    ALARM_SINK = 0x03eb, /* AlarmSink */
                    SMOKE_ALARM = 0x03ec, /* Smoke Alarm */
                    BATTERY_STATUS = 0x03ed, /* Battery Status */
                    Display = 0x03ee, /* Display */
                    LOGICAL_AND_OR = 0x03ef, /* Logical AND/OR */
                    SCENE_CONTROLLER = 0x03f2, /* Scene Controller */
                    Scheduler = 0x03f4, /* Scheduler */
                    ATMOSPHERIC_PRESSURE_SENSOR = 0x03f5, /* Atmospheric Pressure Sensor */
                    GENERAL_PURPOSE_DIGITAL_INPUT = 0x03f6, /* General Purpose Digital Input */
                    GENERAL_PURPOSE_ANALOG_INPUT = 0x03f7, /* General Purpose Analog Input */
                    GENERAL_PURPOSE_TEMPERATURE_SENSOR = 0x03f8, /* General Purpose Temperature Sensor */
                    MULTI_PURPOSE_INPUT = 0x03f9, /* Multi Purpose Input */
                    GENERAL_PURPOSE_DIGITAL_OUTPUT = 0x03fa, /* General Purpose Digital Output */
                    GENERAL_PURPOSE_ANALOG_OUTPUT = 0x03fb, /* General Purpose Analog Output */
                    PRIORITY_SENSOR = 0x03fc, /* Priority Sensor */
                    HEAT_METER = 0x044d, /* Heat Meter */
                    HEAT_COST_ALLOCATOR = 0x044e, /* Heat Cost Allocator */
                    WATER_METER = 0x044f, /* Water Meter */
                    ELECTRICAL_ENERGY_TARIFF_SENSOR = 0x0460, /* Electrical Energy Tariff Sensor */
                    ELECTRICAL_ENERGY_TARIFF_DISPLAY = 0x0461, /* Electrical Energy Tariff Display */
                    TARIFF_SENSOR = 0x0462, /* Tariff Sensor */
                    TARIFF_DISPLAY = 0x0463, /* Tariff Display */
                };

            }

            /* Property Identifier */
            namespace pid {

                namespace device {
                    enum class PropertyIdentifier : uint8_t {
                        PID_ROUTING_COUNT = 0x33, /* Routing Count */
                        PID_MAX_RETRY_COUNT = 0x34, /* MaxRetryCount */
                        PID_ERROR_FLAGS = 0x35, /* Error Flags */
                        PID_PROGMODE = 0x36, /* Programming Mode */
                        PID_PRODUCT_ID = 0x37, /* Product Identification */
                        PID_MAX_APDULENGTH = 0x38, /* Max. APDU-Length */
                        PID_SUBNET_ADDR = 0x39, /* Subnetwork Address */
                        PID_DEVICE_ADDR = 0x3a, /* Device Address */
                        PID_PB_CONFIG = 0x3b, /* PID_Config_Link */
                        PID_ADDR_REPORT = 0x3c, /* Address report */
                        PID_ADDR_CHECK = 0x3d, /* Address Check */
                        PID_OBJECT_VALUE = 0x3e, /* Object Value */
                        PID_OBJECTLINK = 0x3f, /* Object Link */
                        PID_APPLICATION = 0x40, /* Application */
                        PID_PARAMETER = 0x41, /* Parameter */
                        PID_OBJECTADDRESS = 0x42, /* Object Address */
                        PID_PSU_TYPE = 0x43, /* PSU Type */
                        PID_PSU_STATUS = 0x44, /* PSU Status */
                        PID_PSU_ENABLE = 0x45, /* PSU Enable  */
                        PID_DOMAIN_ADDRESS = 0x46, /* Domain Address */
                        PID_IO_LIST = 0x47, /* Interface Object List */
                        PID_MGT_DESCRIPTOR_01 = 0x48, /* Management Descriptor 1 */
                        PID_PL110_PARAM = 0x49, /* PL110 Parameters */
                        PID_RF_REPEAT_COUNTER = 0x4a, /* RF Repeat Counter */
                        PID_RECEIVE_BLOCK_TABLE = 0x4b, /* BiBat Receive Block Table */
                        PID_RANDOM_PAUSE_TABLE = 0x4c, /* BiBat Random Pause Table */
                        PID_RECEIVE_BLOCK_NR = 0x4d, /* BiBat Receive Block Number */
                        PID_HARDWARE_TYPE = 0x4e, /* Hardware Type */
                        PID_RETRANSMITTER_NUMBER = 0x4f, /* BiBat Retransmitter Number */
                        PID_SERIAL_NR_TABLE = 0x50, /* Serial Number Table */
                        PID_BIBATMASTER_ADDRESS = 0x51, /* BiBat Master Individual Address */
                        PID_RF_DOMAIN_ADDRESS = 0x52, /* RF Domain Address */
                        PID_DEVICE_DESCRIPTOR = 0x53, /* Device Descriptor */
                        PID_METERING_FILTER_TABLE = 0x54, /* Metering Filter Table */
                        PID_GROUP_TELEGR_RATE_LIMIT_TIME_BASE = 0x55, /* group telegram rate limitation time base */
                        PID_GROUP_TELEGR_RATE_LIMIT_NO_OF_TELEGR = 0x56, /* group telegram rate limitation number of telegrams */
                        PID_CHANNEL_01_PARAM = 0x65, /* tbd. */
                        PID_CHANNEL_02_PARAM = 0x66, /* tbd. */
                        PID_CHANNEL_03_PARAM = 0x67, /* tbd. */
                        PID_CHANNEL_04_PARAM = 0x68, /* tbd. */
                        PID_CHANNEL_05_PARAM = 0x69, /* tbd. */
                        PID_CHANNEL_06_PARAM = 0x6a, /* tbd. */
                        PID_CHANNEL_07_PARAM = 0x6b, /* tbd. */
                        PID_CHANNEL_08_PARAM = 0x6c, /* tbd. */
                        PID_CHANNEL_09_PARAM = 0x6d, /* tbd. */
                        PID_CHANNEL_10_PARAM = 0x6e, /* tbd. */
                        PID_CHANNEL_11_PARAM = 0x6f, /* tbd. */
                        PID_CHANNEL_12_PARAM = 0x70, /* tbd. */
                        PID_CHANNEL_13_PARAM = 0x71, /* tbd. */
                        PID_CHANNEL_14_PARAM = 0x72, /* tbd. */
                        PID_CHANNEL_15_PARAM = 0x73, /* tbd. */
                        PID_CHANNEL_16_PARAM = 0x74, /* tbd. */
                        PID_CHANNEL_17_PARAM = 0x75, /* tbd. */
                        PID_CHANNEL_18_PARAM = 0x76, /* tbd. */
                        PID_CHANNEL_19_PARAM = 0x77, /* tbd. */
                        PID_CHANNEL_20_PARAM = 0x78, /* tbd. */
                        PID_CHANNEL_21_PARAM = 0x79, /* tbd. */
                        PID_CHANNEL_22_PARAM = 0x7a, /* tbd. */
                        PID_CHANNEL_23_PARAM = 0x7b, /* tbd. */
                        PID_CHANNEL_24_PARAM = 0x7c, /* tbd. */
                        PID_CHANNEL_25_PARAM = 0x7d, /* tbd. */
                        PID_CHANNEL_26_PARAM = 0x7e, /* tbd. */
                        PID_CHANNEL_27_PARAM = 0x7f, /* tbd. */
                        PID_CHANNEL_28_PARAM = 0x80, /* tbd. */
                        PID_CHANNEL_29_PARAM = 0x81, /* tbd. */
                        PID_CHANNEL_30_PARAM = 0x82, /* tbd. */
                        PID_CHANNEL_31_PARAM = 0x83, /* tbd. */
                        PID_CHANNEL_32_PARAM = 0x84 /* tbd. */
                    };
                }

                namespace c_emi_server {
                    enum class PropertyIdentifier : uint8_t {
                        PID_MEDIUM_TYPE = 0x33, /* Media Type(s) supported by cEMI Server */
                        PID_COMM_MODE = 0x34, /* Data Link Layer / Raw (Busmonitor) / Transport L. */
                        PID_MEDIUM_AVAILABILITY = 0x35, /* Bus available (1) or not (0) ? */
                        PID_ADD_INFO_TYPES = 0x36, /* cEMI supported Additional Information Types */
                        PID_TIME_BASE = 0x37, /* Time base used in Extended relative timestamp. */
                        PID_TRANSP_ENABLE = 0x38, /* LL Transparency Mode of cEMI Server */
                        PID_CLIENT_SNA = 0x39, /* Reserved for cEMI Client's Subnetwork Address. */
                        PID_CLIENT_DEVICE_ADDRESS = 0x3a, /* Reserved for cEMI Client?s Device Address. */
                        RESERVED = 0x3d, /* DoA Filter */
                    };
                }

                namespace polling_master {
                    enum class PropertyIdentifier : uint8_t {
                        PID_POLLING_STATE = 0x33, /* Polling State */
                        PID_POLLING_SLAVE_ADDR = 0x34, /* Polling Slave Address */
                        PID_POLL_CYCLE = 0x35 /* Polling Cycle */
                    };
                }

                namespace knxnet_ip_parameter {
                    enum class PropertyIdentifier : uint8_t {
                        PID_PROJECT_INSTALLATION_ID = 0x33,
                        PID_KNX_INDIVIDUAL_ADDRESS = 0x34,
                        PID_ADDITIONAL_INDIVIDUAL_ADDRESSES = 0x35,
                        PID_CURRENT_IP_ASSIGNMENT_METHOD = 0x36,
                        PID_IP_ASSIGNMENT_METHOD = 0x37,
                        PID_IP_CAPABILITIES = 0x38,
                        PID_CURRENT_IP_ADDRESS = 0x39,
                        PID_CURRENT_SUBNET_MASK = 0x3a,
                        PID_CURRENT_DEFAULT_GATEWAY = 0x3b,
                        PID_IP_ADDRESS = 0x3c,
                        PID_SUBNET_MASK = 0x3d,
                        PID_DEFAULT_GATEWAY = 0x3e,
                        PID_DHCP_BOOTP_SERVER = 0x3f,
                        PID_MAC_ADDRESS = 0x40,
                        PID_SYSTEM_SETUP_MULTICAST_ADDRESS = 0x41,
                        PID_ROUTING_MULTICAST_ADDRESS = 0x42,
                        PID_TTL = 0x43,
                        PID_KNXNETIP_DEVICE_CAPABILITIES = 0x44,
                        PID_KNXNETIP_DEVICE_STATE = 0x45,
                        PID_KNXNETIP_ROUTING_CAPABILITIES = 0x46,
                        PID_PRIORITY_FIFO_ENABLED = 0x47,
                        PID_QUEUE_OVERFLOW_TO_IP = 0x48,
                        PID_QUEUE_OVERFLOW_TO_KNX = 0x49,
                        PID_MSG_TRANSMIT_TO_IP = 0x4a,
                        PID_MSG_TRANSMIT_TO_KNX = 0x4b,
                        PID_FRIENDLY_NAME = 0x4c,
                        PID_ROUTING_BUSY_WAIT_TIME = 0x4e
                    };
                }

                enum class PropertyIdentifier : uint8_t {
                    RESERVED = 0x00,
                    PID_OBJECT_TYPE = 0x01, /* Interface Object Type */
                    PID_OBJECT_NAME = 0x02, /* Interface Object Name */
                    PID_SEMAPHOR = 0x03,
                    PID_GROUP_OBJECT_REFERENCE = 0x04,
                    PID_LOAD_STATE_CONTROL = 0x05, /* Load Control */
                    PID_RUN_STATE_CONTROL = 0x06, /* Run Control */
                    PID_TABLE_REFERENCE = 0x07, /* Table Reference */
                    PID_SERVICE_CONTROL = 0x08, /* Service Control */
                    PID_FIRMWARE_REVISION = 0x09, /* Firmware Revision */
                    PID_SERVICES_SUPPORTED = 0x0a, /* Supported Service */
                    PID_SERIAL_NUMBER = 0x0b, /* KNX Serial Number */
                    PID_MANUFACTURER_ID = 0x0c, /* Manufacturer Identifier */
                    PID_PROGRAM_VERSION = 0x0d, /* Application Version */
                    PID_DEVICE_CONTROL = 0x0e, /* Device Control */
                    PID_ORDER_INFO = 0x0f, /* Order Info */
                    PID_PEI_TYPE = 0x10, /* PEI Type */
                    PID_PORT_CONFIGURATION = 0x11, /* PortADDR */
                    PID_POLL_GROUP_SETTINGS = 0x12, /* Pollgroup Settings */
                    PID_MANUFACTURER_DATA = 0x13, /* Manufacturer Data */
                    PID_ENABLE = 0x14,
                    PID_DESCRIPTION = 0x15, /* Description */
                    PID_FILE = 0x16,
                    PID_TABLE = 0x17, /* Table */
                    PID_ENROL = 0x18, /* Interface Object Link */
                    PID_VERSION = 0x19, /* Version */
                    PID_GROUP_OBJECT_LINK = 0x1a, /* Group Address Assignment */
                    PID_MCB_TABLE = 0x1b, /* Memory Control Table */
                    PID_ERROR_CODE = 0x1c, /* Error code */
                    PID_OBJECT_INDEX = 0x1d /* Object Index */
                };
            }

            /* Protocol Data Units */
            class TPDU
            {
                const uint8_t* information_length;
            public:
                APDU apdu;

                void load(const snort::Packet& p, int& offset);

                uint8_t get_info_length() const { return *information_length; }
            };

            class NPDU
            {
                const uint8_t* information_length;
                const uint8_t* tpci;
            public:
                APDU apdu;

                void load(const snort::Packet& p, int& offset);

                uint8_t get_info_length() const { return *information_length; }
                uint8_t get_tpci() const { return ((*tpci) & 0xfc) >> 2;}
            };

            /* Data Link */
            namespace datalink
            {

                class Data
                {
                    const uint8_t* control_field_1;
                    const uint8_t* control_field_2;
                    const uint16_t* source_address;
                    const uint16_t* destination_address;
                public:
                    NPDU npdu;

                    void load(const snort::Packet& p, int& offset);

                    uint8_t get_ctrl1() const { return *control_field_1; }
                    uint8_t get_ctrl2() const { return *control_field_2; }
                    uint16_t get_source_addr() const { return ntohs(*source_address); }
                    uint16_t get_destination_addr() const { return ntohs(*destination_address); }

                    bool is_individual_address() const { return (get_ctrl2() & 0x80) == 0x00; }
                };

                class PollData
                {
                    const uint8_t* control_field_1;
                    const uint8_t* control_field_2;
                    const uint16_t* source_address;
                    const uint16_t* destination_address;
                    const uint8_t* number_of_slots;
                    const uint8_t* poll_data;

                public:
                    void load(const snort::Packet& p, int& offset, MessageCode mc);

                    uint8_t get_ctrl1() const { return *control_field_1; }
                    uint8_t get_ctrl2() const { return *control_field_2; }
                    uint16_t get_source_addr() const { return ntohs(*source_address); }
                    uint16_t get_destination_addr() const { return ntohs(*destination_address); }
                    uint8_t get_number_of_slots() const { return (*number_of_slots) & 0xf; }
                    uint8_t get_poll_data(int i) const { return i < 0 or i > get_number_of_slots() ? 0 : *(poll_data + i); }

                    bool is_individual_address() const { return (get_ctrl2() & 0x80) == 0x00; }
                };

                class Raw
                {
                    const uint8_t* raw_data;
                public:
                    void load(const snort::Packet& p, int& offset);
                };
            }

            class DataLink
            {
            public:
                union {
                    datalink::Data data;
                    datalink::PollData poll_data;
                    datalink::Raw raw;
                };

                void load(const snort::Packet& p, int& offset, MessageCode mc);
            };

            /* Transport */
            class Transport
            {
                const uint8_t* reserved; //[6];
                constexpr static const uint8_t reserved_size = 6;
            public:
                TPDU tpdu;

                void load(const snort::Packet& p, int& offset);
            };

            /* Device Management */
            namespace devmgmt {

                class DataProperty
                {
                    const uint16_t* interface_object_type;
                    const uint8_t* object_instance;
                    const uint8_t* property_id;
                    const uint8_t* number_of_elements;
                    const uint8_t* start_index;

                public:
                    void load(const snort::Packet& p, int& offset, MessageCode mc, uint16_t body_length);
                    static bool is_error_response(MessageCode mc, uint8_t number_of_elements) { return ((mc == MessageCode::M_PROPREAD_CON or mc == MessageCode::M_PROPWRITE_CON) ? (number_of_elements == 0) : false); }

                    iot::InterfaceObjectType get_interface_object_type() const { return static_cast<iot::InterfaceObjectType>(ntohs(*interface_object_type)); }
                    uint8_t get_object_instance() const { return *object_instance; }
                    pid::PropertyIdentifier get_property_id() const { return static_cast<pid::PropertyIdentifier>(*property_id); }
                    uint8_t get_number_of_elements() const { return ((*number_of_elements) >> 4); }
                    uint16_t get_start_index() const { return ((static_cast<uint16_t>(*number_of_elements) << 8) | static_cast<uint16_t>(*start_index)); }

                };

                class FunctionProperty
                {
                    const uint16_t* interface_object_type;
                    const uint8_t* object_instance;
                    const uint8_t* property_id;
                    const uint8_t* return_code;

                public:
                    void load(const snort::Packet& p, int& offset, MessageCode mc, uint16_t body_length);

                    iot::InterfaceObjectType get_interface_object_type() const { return static_cast<iot::InterfaceObjectType>(ntohs(*interface_object_type)); }
                    uint8_t get_object_instance() const { return *object_instance; }
                    pid::PropertyIdentifier get_property_id() const { return static_cast<pid::PropertyIdentifier>(*property_id); }
                    uint8_t get_return_code() const { return *return_code; }
                };

            }

            struct DeviceManagement
            {
                union
                {
                    devmgmt::DataProperty dp;
                    devmgmt::FunctionProperty fp;
                };
                const uint8_t* data;
                uint8_t length;

                void load(const snort::Packet& p, int& offset, MessageCode mc, uint16_t body_length);
            };

        }

        class CEMI {
            const uint8_t* message_code;
            const uint8_t* additional_info_length;

        public:
            cemi::AdditionalInformation additional_information;
            union /* ServiceInformation */
            {
                cemi::DataLink data_link;
                cemi::Transport transport;
                cemi::DeviceManagement device_mgmt;
            };

            void load(const snort::Packet& p, int& offset, uint16_t body_length);

            knxnetip::packet::cemi::MessageCode get_message_code() const { return static_cast<const knxnetip::packet::cemi::MessageCode>(*message_code); }
            uint8_t get_additional_info_length() const { return *additional_info_length; }

            bool is_device_management() const { return ((*message_code) & 0xf0) == 0xf0; }
        };

    }

}

#endif /* KNXNETIP_CEMI_H */
