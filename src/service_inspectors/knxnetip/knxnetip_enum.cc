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
// knxnetip_enum.cc author Alija Sabic <sabic@technikum-wien.at>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "knxnetip_enum.h"

std::map<knxnetip::ServiceType, std::string> knxnetip::service_identifier
{
    { knxnetip::ServiceType::SEARCH_REQ,                "SEARCH_REQUEST" },
    { knxnetip::ServiceType::SEARCH_RES,                "SEARCH_RESPONSE" },
    { knxnetip::ServiceType::DESCRIPTION_REQ,           "DESCRIPTION_REQUEST" },
    { knxnetip::ServiceType::DESCRIPTION_RES,           "DESCRIPTION_RESPONE" },
    { knxnetip::ServiceType::CONNECT_REQ,               "CONNECT_REQUEST" },
    { knxnetip::ServiceType::CONNECT_RES,               "CONNECT_RESPONSE" },
    { knxnetip::ServiceType::CONNECTIONSTATE_REQ,       "CONNECTIONSTATE_REQUEST" },
    { knxnetip::ServiceType::CONNECTIONSTATE_RES,       "CONNECTIONSTATE_RESPONSE" },
    { knxnetip::ServiceType::DISCONNECT_REQ,            "DISCONNECT_REQUEST" },
    { knxnetip::ServiceType::DISCONNECT_RES,            "DISCONNECT_RESPONSE" },
    { knxnetip::ServiceType::DEVICE_CONFIGURATION_REQ,  "DEVICE_CONFIGURATION_REQUEST" },
    { knxnetip::ServiceType::DEVICE_CONFIGURATION_ACK,  "DEVICE_CONFIGURATION_ACK" },
    { knxnetip::ServiceType::TUNNELLING_REQ,            "TUNNELLING_REQUEST" },
    { knxnetip::ServiceType::TUNNELLING_ACK,            "TUNNELLING_ACK" },
    { knxnetip::ServiceType::ROUTING_INDICATION,        "ROUTING_INDICATION" },
    { knxnetip::ServiceType::ROUTING_LOST,              "ROUTING_LOST_MESSAGE" },
    { knxnetip::ServiceType::ROUTING_BUSY,              "ROUTING_BUSY" },
    { knxnetip::ServiceType::REMOTE_DIAG_REQ,           "REMOTE_DIAGNOSTIC_REQUEST" },
    { knxnetip::ServiceType::REMOTE_DIAG_RES,           "REMOTE_DIAGNOSTIC_RESPONSE" },
    { knxnetip::ServiceType::REMOTE_BASIC_CONF_REQ,     "REMOTE_BASIC_CONFIGURATION_REQUEST" },
    { knxnetip::ServiceType::REMOTE_RESET_REQ,          "REMOTE_RESET_REQUEST" }
};

std::map<uint8_t, std::string> knxnetip::service_type
{
    { 0x02, "KNXnet/IP Core" },
    { 0x03, "KNXnet/IP Device Management" },
    { 0x04, "KNXnet/IP Tunneling" },
    { 0x05, "KNXnet/IP Routing" },
    { 0x06, "KNXnet/IP Remote Logging" },
    { 0x07, "KNXnet/IP Remote Configuration and Diagnosis" },
    { 0x08, "KNXnet/IP Object Server" }
};

std::map<uint8_t, std::string> knxnetip::connection_type
{
    { 0x03, "DEVICE_MGMT_CONNECTION" },
    { 0x04, "TUNNEL_CONNECTION" },
    { 0x06, "REMLOG_CONNECTION" },
    { 0x07, "REMCONF_CONNECTION" },
    { 0x08, "OBJSVR_CONNECTION" }
};

std::map<uint8_t, std::string> knxnetip::connect_response_status_code
{
    { 0x00, "E_NO_ERROR - The connection was established successfully" },
    { 0x22, "E_CONNECTION_TYPE - The KNXnet/IP server device does not support the requested connection type" },
    { 0x23, "E_CONNECTION_OPTION - The KNXnet/IP server device does not support one or more requested connection options" },
    { 0x24, "E_NO_MORE_CONNECTIONS - The KNXnet/IP server device could not accept the new data connection (busy)" }
};

std::map<uint8_t, std::string> knxnetip::connectionstate_response_status_code
{
    { 0x00, "E_NO_ERROR - The connection state is normal" },
    { 0x21, "E_CONNECTION_ID - The KNXnet/IP server device could not find an active data connection with the specified ID" },
    { 0x26, "E_DATA_CONNECTION - The KNXnet/IP server device detected an error concerning the data connection with the specified ID" },
    { 0x27, "E_KNX_CONNECTION - The KNXnet/IP server device detected an error concerning the EIB bus / KNX subsystem connection with the specified ID" }
};

std::map<uint8_t, std::string> knxnetip::tunneling_error_code
{
    { 0x00, "E_NO_ERROR - The message was received successfully" },
    { 0x29, "E_TUNNELLING_LAYER - The KNXnet/IP server device does not support the requested tunnelling layer" }
};

std::map<uint8_t, std::string> knxnetip::device_configuration_ack_status_code
{
    { 0x00, "E_NO_ERROR - The message was received successfully" }
};

std::map<knxnetip::packet::dib::Type, std::string> knxnetip::dib_description_type_code
{
    { knxnetip::packet::dib::Type::DEVICE_INFO, "DEVICE_INFO" },
    { knxnetip::packet::dib::Type::SUPP_SVC,    "SUPP_SVC_FAMILIES" },
    { knxnetip::packet::dib::Type::IP_CONF,     "IP_CONFIG" },
    { knxnetip::packet::dib::Type::IP_CURRENT,  "IP_CUR_CONFIG" },
    { knxnetip::packet::dib::Type::KNX_ADDRESS, "KNX_ADDRESSES" },
    { knxnetip::packet::dib::Type::MFR_DATA,    "MFR_DATA" }
};

std::map<knxnetip::packet::dib::MediumCode, std::string> knxnetip::dib_medium_code
{
    { knxnetip::packet::dib::MediumCode::reserved, "reserved" },
    { knxnetip::packet::dib::MediumCode::KNX_TP, "KNX TP" },
    { knxnetip::packet::dib::MediumCode::KNX_PL110, "KNX PL110" },
    { knxnetip::packet::dib::MediumCode::reserved2, "reserved" },
    { knxnetip::packet::dib::MediumCode::KNX_RF, "KNX RF" },
    { knxnetip::packet::dib::MediumCode::KNX_IP, "KNX IP" }
};

std::map<uint8_t, std::string> knxnetip::host_protocol_code
{
    { 0x01, "IPV4_UDP" },
    { 0x02, "IPV4_TCP" }
};

std::map<uint8_t, std::string> knxnetip::ip_assignment_method
{
    { 0x01, "manual" },
    { 0x02, "BootP" },
    { 0x04, "DHCP" },
    { 0x08, "AutoIP" }
};

std::map<uint8_t, std::string> knxnetip::knxlayer_value
{
    { 0x02, "TUNNEL_LINKLAYER" },
    { 0x04, "TUNNEL_RAW"},
    { 0x80, "TUNNEL_BUSMONITOR"}
};

std::map<uint8_t, std::string> knxnetip::selector_type
{
    { 0x01, "PrgMode Selector" },
    { 0x02, "MAC Selector" }
};

std::map<uint8_t, std::string> knxnetip::reset_code
{
    { 0x01, "Restart" },
    { 0x02, "Master Reset" }
};

/*for CEMI*/

std::map<knxnetip::packet::cemi::MessageCode, std::string> knxnetip::cemi_messagecode
{
    { knxnetip::packet::cemi::MessageCode::L_RAW_REQ,              "L_Raw.req" },
    { knxnetip::packet::cemi::MessageCode::L_DATA_REQ,             "L_Data.req" },
    { knxnetip::packet::cemi::MessageCode::L_POLL_DATA_REQ,        "L_Poll_Data.req" },
    { knxnetip::packet::cemi::MessageCode::L_POLL_DATA_CON,        "L_Poll_Data.con" },
    { knxnetip::packet::cemi::MessageCode::L_DATA_IND,             "L_Data.ind" },
    { knxnetip::packet::cemi::MessageCode::L_BUSMON_IND,           "L_Busmon.ind" },
    { knxnetip::packet::cemi::MessageCode::L_RAW_IND,              "L_Raw.ind" },
    { knxnetip::packet::cemi::MessageCode::L_DATA_CON,             "L_Data.con" },
    { knxnetip::packet::cemi::MessageCode::L_RAW_CON,              "L_Raw.con" },
    { knxnetip::packet::cemi::MessageCode::T_DATA_CONNEC_REQ,      "T_Data_Connected.req" },
    { knxnetip::packet::cemi::MessageCode::T_DATA_INDV_REQ,        "T_Data_Individual.req" },
    { knxnetip::packet::cemi::MessageCode::T_DATA_CONNEC_IND,      "T_Data_Connected.ind" },
    { knxnetip::packet::cemi::MessageCode::T_DATA_INDV_IND,        "T_Data_Individual.ind" },
    { knxnetip::packet::cemi::MessageCode::M_RESET_IND,            "M_Reset.ind" },
    { knxnetip::packet::cemi::MessageCode::M_RESET_REQ,            "M_Reset.req" },
    { knxnetip::packet::cemi::MessageCode::M_PROPWRITE_CON,        "M_PropWrite.con" },
    { knxnetip::packet::cemi::MessageCode::M_PROPWRITE_REQ,        "M_PropWrite.req" },
    { knxnetip::packet::cemi::MessageCode::M_PROPINFO_IND,         "M_PropInfo.ind" },
    { knxnetip::packet::cemi::MessageCode::M_FUNCPROPCOM_REQ,      "M_FuncPropCommand.req" },
    { knxnetip::packet::cemi::MessageCode::M_FUNCPROPSTATREAD_REQ, "M_FuncPropStateRead.req" },
    { knxnetip::packet::cemi::MessageCode::M_FUNCPROPCOM_CON,      "M_FuncPropCommand/StateRead.con" },
    { knxnetip::packet::cemi::MessageCode::M_PROPREAD_CON,         "M_PropRead.con" },
    { knxnetip::packet::cemi::MessageCode::M_PROPREAD_REQ,         "M_PropRead.req" }
};

std::map<knxnetip::packet::cemi::add_info::TypeId, std::string> knxnetip::cemi_add_type_id
{
    { knxnetip::packet::cemi::add_info::TypeId::RESERVED,    "reserved" },
    { knxnetip::packet::cemi::add_info::TypeId::PL_INFO,     "PL Info" },
    { knxnetip::packet::cemi::add_info::TypeId::RF_INFO,     "RF Info" },
    { knxnetip::packet::cemi::add_info::TypeId::BUSMON_INFO, "Busmonitor Info" },
    { knxnetip::packet::cemi::add_info::TypeId::TIME_REL,    "relative timestamp" },
    { knxnetip::packet::cemi::add_info::TypeId::TIME_DELAY,  "time delay until send" },
    { knxnetip::packet::cemi::add_info::TypeId::EXEND_TIME,  "extended relative timestamp" },
    { knxnetip::packet::cemi::add_info::TypeId::BIBAT_INFO,  "BiBat information" },
    { knxnetip::packet::cemi::add_info::TypeId::RF_MULTI,    "RF Multi information" },
    { knxnetip::packet::cemi::add_info::TypeId::PREAMBEL,    "Preamble and postamble" },
    { knxnetip::packet::cemi::add_info::TypeId::RF_FAST_ACK, "RF Fast Ack information" },
    { knxnetip::packet::cemi::add_info::TypeId::MANU_DATA,   "Manufacturer specific data" },
    { knxnetip::packet::cemi::add_info::TypeId::RESERVED2,   "reserved"}
};

std::map<uint8_t, std::string> knxnetip::cemi_tpci_val
{
    { 0x0, "UDT (Unnumbered Data Packet)" },
    { 0x2, "UCD (Unnumbered)" },
    { 0x1, "NDT (Numbered Data Packet)" },
    { 0x3, "NCD (Numbered Control Data)" }
};

std::map<uint16_t, std::string> knxnetip::cemi_apci_code
{
    { 0x000, "A_GroupValue_Read" },
    { 0x001, "A_GroupValue_Response" },
    { 0x002, "A_GroupValue_Write" },
    { 0x0C0, "A_IndividualAddress_Write" },
    { 0x100, "A_IndividualAddress_Read" },
    { 0x140, "A_IndividualAddress_Response" },
    { 0x006, "A_ADC_Read" },
    { 0x1C0, "A_ADC_Response" },
    { 0x1C4, "A_SystemNetworkParameter_Read" },
    { 0x1C9, "A_SystemNetworkParameter_Response" },
    { 0x1CA, "A_SystemNetworkParameter_Write" },
    { 0x020, "A_Memory_Read" },
    { 0x024, "A_Memory_Response" },
    { 0x028, "A_Memory_Write" },
    { 0x2C0, "A_UserMemory_Read" },
    { 0x2C1, "A_UserMemory_Response" },
    { 0x2C2, "A_UserMemory_Write" },
    { 0x2C5, "A_UserManufacturerInfo_Read" },
    { 0x2C6, "A_UserManufacturerInfo_Response" },
    { 0x2C7, "A_FunctionPropertyCommand" },
    { 0x2C8, "A_FunctionPropertyState_Read" },
    { 0x2C9, "A_FunctionPropertyState_Response" },
    { 0x300, "A_DeviceDescriptor_Read" },
    { 0x340, "A_DeviceDescriptor_Response" },
    { 0x380, "A_Restart" },
    { 0x3D1, "A_Authorize_Request" },
    { 0x3D2, "A_Authorize_Response" },
    { 0x3D3, "A_Key_Write" },
    { 0x3D4, "A_Key_Response" },
    { 0x3D5, "A_PropertyValue_Read" },
    { 0x3D6, "A_PropertyValue_Response" },
    { 0x3D7, "A_PropertyValue_Write" },
    { 0x3D8, "A_PropertyDescription_Read" },
    { 0x3D9, "A_PropertyDescription_Response" },
    { 0x3DA, "A_NetworkParameter_Read" },
    { 0x3DB, "A_NetworkParameter_Response" },
    { 0x3DC, "A_IndividualAddressSerialNumber_Read" },
    { 0x3DD, "A_IndividualAddressSerialNumber_Response" },
    { 0x3DF, "A_IndividualAddressSerialNumber_Write" },
    { 0x3E0, "A_DomainAddress_Write" },
    { 0x3E1, "A_DomainAddress_Read" },
    { 0x3E2, "A_DomainAddress_Response" },
    { 0x3E3, "A_DomainAddressSelective_Read" },
    { 0x3E4, "A_NetworkParameter_Write" },
    { 0x3E5, "A_Link_Read" },
    { 0x3E6, "A_Link_Response" },
    { 0x3E7, "A_Link_Write" },
    { 0x3E8, "A_GroupPropValue_Read" },
    { 0x3E9, "A_GroupPropValue_Response" },
    { 0x3EA, "A_GroupPropValue_Write" },
    { 0x3EB, "A_GroupPropValue_InfoReport" },
    { 0x3EC, "A_DomainAddressSerialNumber_Read" },
    { 0x3ED, "A_DomainAddressSerialNumber_Response" },
    { 0x3EE, "A_DomainAddressSerialNumber_Write" },
    { 0x3F0, "A_FileStream_InforReport" }
};

std::map<knxnetip::packet::cemi::iot::InterfaceObjectType, std::string> cemi_interfacobject
{
    { knxnetip::packet::cemi::iot::InterfaceObjectType::DEVICE_OBJECT, "DEVICE_OBJECT" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::ADDRESSTABLE_OBJECT, "ADDRESSTABLE_OBJECT" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::ASSOCIATIONTABLE_OBJECT, "ASSOCIATIONTABLE_OBJECT" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::APPLICATIONPROGRAM_OBJECT, "APPLICATIONPROGRAM_OBJECT" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::INTERFACEPROGRAM_OBJECT, "INTERFACEPROGRAM_OBJECT" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::KNX_OBJECT_ASSOCIATIONTABLE_OBJECT, "KNX_OBJECT_ASSOCIATIONTABLE_OBJECT" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::ROUTER_OBJECT, "ROUTER_OBJECT" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::LTE_ADDRESS_ROUTING_TABLE_OBJECT, "LTE_ADDRESS_ROUTING_TABLE_OBJECT" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::C_EMI_SERVER_OBJECT, "C_EMI_SERVER_OBJECT" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::GROUP_OBJECT_TABLE_OBJECT, "GROUP_OBJECT_TABLE_OBJECT" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::POLLING_MASTER, "POLLING_MASTER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::KNXNET_IP_PARAMETER_OBJECT, "KNXNET_IP_PARAMETER_OBJECT" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::RESERVED, "RESERVED" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::FILE_SERVER_OBJECT, "FILE_SERVER_OBJECT" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::ROOM_SETPOINT_MANAGER_HVAC_MODE_DRIVEN, "ROOM_SETPOINT_MANAGER_HVAC_MODE_DRIVEN" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::ROOM_SETPOINT_MANAGER_TEMPERATURE_DRIVEN, "ROOM_SETPOINT_MANAGER_TEMPERATURE_DRIVEN" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::SETPOINT_MANAGER_AIR_QUALITY, "SETPOINT_MANAGER_AIR_QUALITY" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::SETPOINT_MANAGER_RELATIVE_HUMIDITY, "SETPOINT_MANAGER_RELATIVE_HUMIDITY" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::PROGRAMTO_HVAC_MODE_CONVERSION, "PROGRAMTO_HVAC_MODE_CONVERSION" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::HVAC_EMERGENCY_SOURCE, "HVAC_EMERGENCY_SOURCE" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::BUILDING_OCC_MODE_SOURCE, "BUILDING_OCC_MODE_SOURCE" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::HVAC_MODE_SCHEDULER, "HVAC_MODE_SCHEDULER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::DHW_MODE_SCHEDULER, "DHW_MODE_SCHEDULER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::DHW_CIRCULATION_PUMP_SCHEDULER, "DHW_CIRCULATION_PUMP_SCHEDULER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::ABSOLUTE_ROOM_TEMPERATURE_SETPOINT_SCHEDULER, "ABSOLUTE_ROOM_TEMPERATURE_SETPOINT_SCHEDULER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::HVAC_OPTIMISER, "HVAC_OPTIMISER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::FLOW_TEMPERATURE_CONTROLLER, "FLOW_TEMPERATURE_CONTROLLER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::BURNER_CONTROLLER, "BURNER_CONTROLLER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::BOILER_CONTROLLER, "BOILER_CONTROLLER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::HEAT_PRODUCER_MANAGER, "HEAT_PRODUCER_MANAGER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::HEAT_PRODUCER_MANAGERFOR_BST, "HEAT_PRODUCER_MANAGERFOR_BST" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::HPMFOR_BSTIN_BOILERSUB_CASCADE, "HPMFOR_BSTIN_BOILERSUB_CASCADE" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::HEAT_FLOW_DEMAND_MANAGER, "HEAT_FLOW_DEMAND_MANAGER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::AUXILIARY_HEAT_DEMAND, "AUXILIARY_HEAT_DEMAND" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::AUXILIARY_HEATING_DEMAND_PERCENT, "AUXILIARY_HEATING_DEMAND_PERCENT" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::HEATING_DEMAND_TRANSFORMER_ROOM_TEMPERATURE, "HEATING_DEMAND_TRANSFORMER_ROOM_TEMPERATURE" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::HEATING_DEMAND_TRANSFORMERFOR_AIR_HANDLING_UNITS, "HEATING_DEMAND_TRANSFORMERFOR_AIR_HANDLING_UNITS" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::RADIATOR_HEATING_ENERGY_DEMAND_TRANSFORMER_TU, "RADIATOR_HEATING_ENERGY_DEMAND_TRANSFORMER_TU" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::AIR_HEATER_ENERGY_DEMAND_TRANSFORMER_TU, "AIR_HEATER_ENERGY_DEMAND_TRANSFORMER_TU" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::HEATING_ZONE_CONTROLLER, "HEATING_ZONE_CONTROLLER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::HEATING_INDIVIDUAL_ROOM_CONTROLLER, "HEATING_INDIVIDUAL_ROOM_CONTROLLER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::HEATING_DEMAND_TRANSFORMER_ACTUATOR_POSITION, "HEATING_DEMAND_TRANSFORMER_ACTUATOR_POSITION" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::HEATING_ROOM_DEMAND_MANAGER, "HEATING_ROOM_DEMAND_MANAGER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::DOMESTIC_HOT_WATER_SETPOINT_MANAGER, "DOMESTIC_HOT_WATER_SETPOINT_MANAGER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::DOMESTIC_HOT_WATER_CONTROLLER, "DOMESTIC_HOT_WATER_CONTROLLER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::DHW_CIRCULATION_PUMP_CONTROLLER, "DHW_CIRCULATION_PUMP_CONTROLLER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::DHW_TEMPERATURE_SENSOR, "DHW_TEMPERATURE_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::DHW_USER_SETTINGS, "DHW_USER_SETTINGS" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::SOLAR_DOMESTIC_HOT_WATER_CONTROLLER, "SOLAR_DOMESTIC_HOT_WATER_CONTROLLER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::COLLECTOR_TEMPERATURE_SENSOR, "COLLECTOR_TEMPERATURE_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::CHILLER_CONTROLLER, "CHILLER_CONTROLLER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::COLD_WATER_PODUCER_MANAGER, "COLD_WATER_PODUCER_MANAGER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::RE_COOLING_CONTROL, "RE_COOLING_CONTROL" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::COOLING_FLOW_DEMAND_MANAGER, "COOLING_FLOW_DEMAND_MANAGER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::AUXILIARY_COOLING_DEMAND, "AUXILIARY_COOLING_DEMAND" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::AUXILIARY_COOLING_DEMAND_PERCENT, "AUXILIARY_COOLING_DEMAND_PERCENT" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::COOLING_DEMAND_TRANSFORMERFOR_AIR_HANDLING_UNITS, "COOLING_DEMAND_TRANSFORMERFOR_AIR_HANDLING_UNITS" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::CHILLED_CEILING_ENERGY_DEMAND_TRANSFORMER_TU, "CHILLED_CEILING_ENERGY_DEMAND_TRANSFORMER_TU" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::AIR_COOLER_ENERGY_DEMAND_TRANSFORMER_TU, "AIR_COOLER_ENERGY_DEMAND_TRANSFORMER_TU" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::COOLING_ZONE_CONTROLLER, "COOLING_ZONE_CONTROLLER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::AIR_HANDLING_UNIT_CONTROLLER, "AIR_HANDLING_UNIT_CONTROLLER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::SUPPLY_AIR_TEMPERATURE_CONTROLLER, "SUPPLY_AIR_TEMPERATURE_CONTROLLER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::VENTILATION_DEMAND_TRANSFORMER_TU, "VENTILATION_DEMAND_TRANSFORMER_TU" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::RADIATOR_ROOM_CONTROL_TU, "RADIATOR_ROOM_CONTROL_TU" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::RADIATORAND_CHILLED_CEILING_ROOM_CONTROL, "RADIATORAND_CHILLED_CEILING_ROOM_CONTROL" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::FANCOIL_CONTROL, "FANCOIL_CONTROL" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::WATER_HEAT_PUMP_CONTROLFOR_RINGWATER, "WATER_HEAT_PUMP_CONTROLFOR_RINGWATER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::SPLIT_UNIT_CONTROL, "SPLIT_UNIT_CONTROL" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::VAV_CONTROL_DISCHARGE_AIR, "VAV_CONTROL_DISCHARGE_AIR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::VAV_CONTROL_EXTRACT_AIR, "VAV_CONTROL_EXTRACT_AIR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::HEATINGAND_COOLING_INDIVIDUAL_ROOM_CONTROLLER, "HEATINGAND_COOLING_INDIVIDUAL_ROOM_CONTROLLER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::COOLING_DEMAND_TRANSFORMER_ROOM_TEMPERATURE, "COOLING_DEMAND_TRANSFORMER_ROOM_TEMPERATURE" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::KNXTO_FIL_PILOTE_CONVERTER_KFP, "KNXTO_FIL_PILOTE_CONVERTER_KFP" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::OUTSIDE_TEMPERATURE_SENSOR, "OUTSIDE_TEMPERATURE_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::ROOM_TEMPERATURE_SENSOR, "ROOM_TEMPERATURE_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::SUPPLY_AIR_TEMPERATURE_SENSOR, "SUPPLY_AIR_TEMPERATURE_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::RETURN_AIR_TEMPERATURE_SENSOR, "RETURN_AIR_TEMPERATURE_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::FLOW_WATER_TEMPERATURE_SENSOR, "FLOW_WATER_TEMPERATURE_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::RETURN_WATER_TEMPERATURE_SENSOR, "RETURN_WATER_TEMPERATURE_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::CONDENSER_FLOW_WATER_TEMPERATURE_SENSOR, "CONDENSER_FLOW_WATER_TEMPERATURE_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::CONDENSER_RETURN_WATER_TEMPERATURE_SENSOR, "CONDENSER_RETURN_WATER_TEMPERATURE_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::DISCHARGE_AIR_TEMPERATURE_SENSOR, "DISCHARGE_AIR_TEMPERATURE_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::FLOOR_TEMPERATURE_SENSOR, "FLOOR_TEMPERATURE_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::OUTSIDE_AQ_SENSOR, "OUTSIDE_AQ_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::ROOM_AQ_SENSOR, "ROOM_AQ_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::SUPPLY_AQ_SENSOR, "SUPPLY_AQ_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::RETURN_AQ_SENSOR, "RETURN_AQ_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::OUTSIDE_RELATIVE_HUMIDITY_SENSOR, "OUTSIDE_RELATIVE_HUMIDITY_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::ROOM_RELATIVE_HUMIDITY_SENSOR, "ROOM_RELATIVE_HUMIDITY_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::SUPPLY_AIR_RELATIVE_HUMIDITY_SENSOR, "SUPPLY_AIR_RELATIVE_HUMIDITY_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::RETURN_AIR_RELATIVE_HUMIDITY_SENSOR, "RETURN_AIR_RELATIVE_HUMIDITY_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::AIR_CHANGE_OVER_STATUS_SENSOR, "AIR_CHANGE_OVER_STATUS_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::WATER_CHANGE_OVER_STATUS_SENSOR, "WATER_CHANGE_OVER_STATUS_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::WINDOW_SWITCH, "WINDOW_SWITCH" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::DEW_POINT_STATUS_SENSOR, "DEW_POINT_STATUS_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::PRESENCE_DETECTOR, "PRESENCE_DETECTOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::WIND_SPEED_SENSOR, "WIND_SPEED_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::SUN_INTENSITY_SENSOR, "SUN_INTENSITY_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::HVAC_VALVE_ACTUATOR, "HVAC_VALVE_ACTUATOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::COMPRESSOR_INVERTING_VALVE_ACTUATOR, "COMPRESSOR_INVERTING_VALVE_ACTUATOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::AIR_DAMPER_ACTUATOR, "AIR_DAMPER_ACTUATOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::ELECTRICAL_HEATING_ELEMENT_ACTUATOR, "ELECTRICAL_HEATING_ELEMENT_ACTUATOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::FAN_SPEED_ACTUATOR, "FAN_SPEED_ACTUATOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::COMPRESSOR_ACTUATOR, "COMPRESSOR_ACTUATOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::USER_HVAC_ROOM_SETTINGS, "USER_HVAC_ROOM_SETTINGS" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::ROOM_TEMPERATURE_SETPOINT_ABSOLUTE_SETTING, "ROOM_TEMPERATURE_SETPOINT_ABSOLUTE_SETTING" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::USER_AIR_QUALITY_SETPOINT_SETTING, "USER_AIR_QUALITY_SETPOINT_SETTING" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::USER_RELATIVE_HUMIDITY_SETPOINT_SETTING, "USER_RELATIVE_HUMIDITY_SETPOINT_SETTING" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::USER_HVAC_DISPLAY, "USER_HVAC_DISPLAY" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::USER_PRESENCE_SWITCH, "USER_PRESENCE_SWITCH" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::USER_CHANGE_OVER_SETTINGS, "USER_CHANGE_OVER_SETTINGS" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::USER_FAN_SPEED_SETTING, "USER_FAN_SPEED_SETTING" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::USER_ENABLE_ALTERNATIVE_ROOM_TEMPERATURE_SETPOINT, "USER_ENABLE_ALTERNATIVE_ROOM_TEMPERATURE_SETPOINT" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::FB_SCENE_SENSOR, "FB_SCENE_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::TIMED_SENSOR, "TIMED_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::ROOM_LIGHT_SETPOINT, "ROOM_LIGHT_SETPOINT" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::INDOOR_BRIGHTNESS_SENSOR, "INDOOR_BRIGHTNESS_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::INDOOR_LUMINANCE_SENSOR, "INDOOR_LUMINANCE_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::MOTION_DETECTOR, "MOTION_DETECTOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::ROOM_LIGHT_CONTROLLER, "ROOM_LIGHT_CONTROLLER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::LIGHT_SWITCHING_ACTUATOR_BASIC, "LIGHT_SWITCHING_ACTUATOR_BASIC" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::DIMMING_ACTUATOR_BASIC, "DIMMING_ACTUATOR_BASIC" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::FB_DIMMING_SENSOR_BASIC, "FB_DIMMING_SENSOR_BASIC" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::FB_SWITCHING_SENSOR_BASIC, "FB_SWITCHING_SENSOR_BASIC" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::FB_SUNBLIND_ACTUATOR_BASIC, "FB_SUNBLIND_ACTUATOR_BASIC" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::FB_SUNBLIND_SENSOR_BASIC, "FB_SUNBLIND_SENSOR_BASIC" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::FB_WIND_SENSOR_FB_WIND_ALARM, "FB_WIND_SENSOR_FB_WIND_ALARM" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::FB_RAIN_SENSOR_FB_RAIN_ALARM, "FB_RAIN_SENSOR_FB_RAIN_ALARM" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::FB_FROST_SENSOR, "FB_FROST_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::SYSTEM_CLOCK, "SYSTEM_CLOCK" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::ALARM_SOURCE, "ALARM_SOURCE" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::ALARM_SINK, "ALARM_SINK" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::SMOKE_ALARM, "SMOKE_ALARM" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::BATTERY_STATUS, "BATTERY_STATUS" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::Display, "Display" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::LOGICAL_AND_OR, "LOGICAL_AND_OR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::SCENE_CONTROLLER, "SCENE_CONTROLLER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::Scheduler, "Scheduler" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::ATMOSPHERIC_PRESSURE_SENSOR, "ATMOSPHERIC_PRESSURE_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::GENERAL_PURPOSE_DIGITAL_INPUT, "GENERAL_PURPOSE_DIGITAL_INPUT" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::GENERAL_PURPOSE_ANALOG_INPUT, "GENERAL_PURPOSE_ANALOG_INPUT" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::GENERAL_PURPOSE_TEMPERATURE_SENSOR, "GENERAL_PURPOSE_TEMPERATURE_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::MULTI_PURPOSE_INPUT, "MULTI_PURPOSE_INPUT" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::GENERAL_PURPOSE_DIGITAL_OUTPUT, "GENERAL_PURPOSE_DIGITAL_OUTPUT" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::GENERAL_PURPOSE_ANALOG_OUTPUT, "GENERAL_PURPOSE_ANALOG_OUTPUT" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::PRIORITY_SENSOR, "PRIORITY_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::HEAT_METER, "HEAT_METER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::HEAT_COST_ALLOCATOR, "HEAT_COST_ALLOCATOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::WATER_METER, "WATER_METER" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::ELECTRICAL_ENERGY_TARIFF_SENSOR, "ELECTRICAL_ENERGY_TARIFF_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::ELECTRICAL_ENERGY_TARIFF_DISPLAY, "ELECTRICAL_ENERGY_TARIFF_DISPLAY" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::TARIFF_SENSOR, "TARIFF_SENSOR" },
    { knxnetip::packet::cemi::iot::InterfaceObjectType::TARIFF_DISPLAY, "TARIFF_DISPLAY" }
};

std::map<uint8_t, std::string> knxnetip::cemi_propertyid
{
    {  1, "PID_OBJECT_TYPE" },
    {  8, "PID_SERVICE_CONTROL" },
    {  9, "PID_FIRMWARE_REVISION" },
    { 11, "PID_SERIAL_NUMBER" },
    { 12, "PID_MANUFACTURER_ID" },
    { 14, "PID_DEVICE_CONTROL" },
    { 19, "PID_MANUFACTURE_DATA" },
    { 51, "PID_ROUTING_COUNT" },
    { 52, "PID_MAX_RETRY_COUNT " },
    { 53, "PID_ERROR_FLAGS" },
    { 54, "PID_PROGMODE" },
    { 56, "PID_MAX_APDULENGTH" },
    { 57, "PID_SUBNET_ADDR" },
    { 58, "PID_DEVICE_ADDR" },
    { 59, "PID_PB_CONFIG" },
    { 60, "PID_ADDR_REPORT" },
    { 61, "PID_ADDR_CHECK" },
    { 62, "PID_OBJECT_VALUE" },
    { 63, "PID_OBJECTLINK" },
    { 64, "PID_APPLICATION" },
    { 65, "PID_PARAMETER" },
    { 66, "PID_OBJECTADDRESS" },
    { 67, "PID_PSU_TYPE" },
    { 68, "PID_PSU_STATUS" },
    { 70, "PID_DOMAIN_ADDR"},
    { 71, "PID_IO_LIST"}
};

std::map<knxnetip::packet::cemi::pid::PropertyIdentifier, std::string> knxnetip::cemi_propertyid_default
{
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_OBJECT_TYPE, "PID_OBJECT_TYPE" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_OBJECT_NAME, "PID_OBJECT_NAME" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_SEMAPHOR, "PID_SEMAPHOR" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_GROUP_OBJECT_REFERENCE, "PID_GROUP_OBJECT_REFERENCE" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_LOAD_STATE_CONTROL, "PID_LOAD_STATE_CONTROL" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_RUN_STATE_CONTROL, "PID_RUN_STATE_CONTROL" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_TABLE_REFERENCE, "PID_TABLE_REFERENCE" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_SERVICE_CONTROL, "PID_SERVICE_CONTROL" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_FIRMWARE_REVISION, "PID_FIRMWARE_REVISION" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_SERVICES_SUPPORTED, "PID_SERVICES_SUPPORTED" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_SERIAL_NUMBER, "PID_SERIAL_NUMBER" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_MANUFACTURER_ID, "PID_MANUFACTURER_ID" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_PROGRAM_VERSION, "PID_PROGRAM_VERSION" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_DEVICE_CONTROL, "PID_DEVICE_CONTROL" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_ORDER_INFO, "PID_ORDER_INFO" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_PEI_TYPE, "PID_PEI_TYPE" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_PORT_CONFIGURATION, "PID_PORT_CONFIGURATION" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_POLL_GROUP_SETTINGS, "PID_POLL_GROUP_SETTINGS" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_MANUFACTURER_DATA, "PID_MANUFACTURER_DATA" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_ENABLE, "PID_ENABLE" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_DESCRIPTION, "PID_DESCRIPTION" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_FILE, "PID_FILE" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_TABLE, "PID_TABLE" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_ENROL, "PID_ENROL" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_VERSION, "PID_VERSION" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_GROUP_OBJECT_LINK, "PID_GROUP_OBJECT_LINK" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_MCB_TABLE, "PID_MCB_TABLE" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_ERROR_CODE, "PID_ERROR_CODE" },
    { knxnetip::packet::cemi::pid::PropertyIdentifier::PID_OBJECT_INDEX, "PID_OBJECT_INDEX" }
};

std::map<knxnetip::packet::cemi::pid::device::PropertyIdentifier, std::string> cemi_propertyid_default_device
{
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_ROUTING_COUNT, "PID_ROUTING_COUNT" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_MAX_RETRY_COUNT, "PID_MAX_RETRY_COUNT" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_ERROR_FLAGS, "PID_ERROR_FLAGS" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_PROGMODE, "PID_PROGMODE" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_PRODUCT_ID, "PID_PRODUCT_ID" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_MAX_APDULENGTH, "PID_MAX_APDULENGTH" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_SUBNET_ADDR, "PID_SUBNET_ADDR" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_DEVICE_ADDR, "PID_DEVICE_ADDR" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_PB_CONFIG, "PID_PB_CONFIG" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_ADDR_REPORT, "PID_ADDR_REPORT" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_ADDR_CHECK, "PID_ADDR_CHECK" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_OBJECT_VALUE, "PID_OBJECT_VALUE" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_OBJECTLINK, "PID_OBJECTLINK" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_APPLICATION, "PID_APPLICATION" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_PARAMETER, "PID_PARAMETER" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_OBJECTADDRESS, "PID_OBJECTADDRESS" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_PSU_TYPE, "PID_PSU_TYPE" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_PSU_STATUS, "PID_PSU_STATUS" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_PSU_ENABLE, "PID_PSU_ENABLE" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_DOMAIN_ADDRESS, "PID_DOMAIN_ADDRESS" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_IO_LIST, "PID_IO_LIST" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_MGT_DESCRIPTOR_01, "PID_MGT_DESCRIPTOR_01" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_PL110_PARAM, "PID_PL110_PARAM" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_RF_REPEAT_COUNTER, "PID_RF_REPEAT_COUNTER" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_RECEIVE_BLOCK_TABLE, "PID_RECEIVE_BLOCK_TABLE" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_RANDOM_PAUSE_TABLE, "PID_RANDOM_PAUSE_TABLE" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_RECEIVE_BLOCK_NR, "PID_RECEIVE_BLOCK_NR" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_HARDWARE_TYPE, "PID_HARDWARE_TYPE" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_RETRANSMITTER_NUMBER, "PID_RETRANSMITTER_NUMBER" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_SERIAL_NR_TABLE, "PID_SERIAL_NR_TABLE" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_BIBATMASTER_ADDRESS, "PID_BIBATMASTER_ADDRESS" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_RF_DOMAIN_ADDRESS, "PID_RF_DOMAIN_ADDRESS" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_DEVICE_DESCRIPTOR, "PID_DEVICE_DESCRIPTOR" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_METERING_FILTER_TABLE, "PID_METERING_FILTER_TABLE" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_GROUP_TELEGR_RATE_LIMIT_TIME_BASE, "PID_GROUP_TELEGR_RATE_LIMIT_TIME_BASE" },
    { knxnetip::packet::cemi::pid::device::PropertyIdentifier::PID_GROUP_TELEGR_RATE_LIMIT_NO_OF_TELEGR, "PID_GROUP_TELEGR_RATE_LIMIT_NO_OF_TELEGR" }
};

std::map<knxnetip::packet::cemi::pid::polling_master::PropertyIdentifier, std::string> cemi_propertyid_default_polling_master
{
    { knxnetip::packet::cemi::pid::polling_master::PropertyIdentifier::PID_POLLING_STATE, "PID_POLLING_STATE" },
    { knxnetip::packet::cemi::pid::polling_master::PropertyIdentifier::PID_POLLING_SLAVE_ADDR, "PID_POLLING_SLAVE_ADDR" },
    { knxnetip::packet::cemi::pid::polling_master::PropertyIdentifier::PID_POLL_CYCLE, "PID_POLL_CYCLE" }
};

std::map<knxnetip::packet::cemi::ErrorCode, std::string> knxnetip::cemi_error_code
{
    { knxnetip::packet::cemi::ErrorCode::UNSPECIFIED_ERROR, "Unspecified Error" },
    { knxnetip::packet::cemi::ErrorCode::OUT_OF_RANGE, "Out of range" },
    { knxnetip::packet::cemi::ErrorCode::OUT_OF_MAXRANGE, "Out of maxrange" },
    { knxnetip::packet::cemi::ErrorCode::OUT_OF_MINRANGE, "Out of minrange" },
    { knxnetip::packet::cemi::ErrorCode::MEMORY_ERROR, "Memory Error" },
    { knxnetip::packet::cemi::ErrorCode::READ_ONLY, "Read only" },
    { knxnetip::packet::cemi::ErrorCode::ILLEGAL_COMMAND, "Illegal command" },
    { knxnetip::packet::cemi::ErrorCode::VOID_DP, "Void DP" },
    { knxnetip::packet::cemi::ErrorCode::TYPE_CONFLICT, "Type conflict" },
    { knxnetip::packet::cemi::ErrorCode::PROP_INDEX_RANGE_ERROR, "Prop. Index range error" },
    { knxnetip::packet::cemi::ErrorCode::VALUE_NOT_WRITEABLE_NOW, "Value temporarily not writeable" }
};

std::map<uint8_t, std::string> knxnetip::cemi_bibat_ctrl
{
    { 0x0, "asynchr. RF frame" },
    { 0x1, "Fast_ACK" },
    { 0x4, "synchronous L_Data frames" },
    { 0x5, "Sync frame" },
    { 0x6, "Help Call" },
    { 0x7, "Help Call Response" }
};
