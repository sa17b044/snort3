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
// knxnetip_packet_util.cc author Alija Sabic <sabic@technikum-wien.at>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
//#include "detection/detection_engine.h"
//#include "knxnetip_module.h"
//#include "knxnetip_tables.h"
#include "knxnetip_util.h"
#include "knxnetip_packet_util.h"

/* HPAI */
void knxnetip::packet::HPAI::load(const snort::Packet& p, int& offset)
{
    uint8_t hpai_length = 8;

    util::get(structure_length, p.data, offset, p.dsize);
    util::get(host_protocol, p.data, offset, p.dsize);
    util::get(ip, p.data, offset, p.dsize);
    util::get(port, p.data, offset, p.dsize);

    if (get_structure_length() != hpai_length) {
        /*FIXME: alert */
        snort::DetectionEngine::queue_event(GID_KNXNETIP, KNXNETIP_DUMMY);
    }
}

/* DIB */
void knxnetip::packet::DIB::load(const snort::Packet& p, int& offset)
{
    uint8_t dib_header_length = 2;

    util::get(dib_structure_length, p.data, offset, p.dsize);
    util::get(dib_type, p.data, offset, p.dsize);

    switch(get_dib_type())
    {
        case dib::Type::DEVICE_INFO:
            device_info.load(p, offset);
            break;

        case dib::Type::SUPP_SVC:
            supp_svc_families.load(p, offset, get_dib_structure_length() - dib_header_length);
            break;

        case dib::Type::IP_CONF:
            ip_config.load(p, offset);
            break;

        case dib::Type::IP_CURRENT:
            ip_current.load(p, offset);
            break;

        case dib::Type::KNX_ADDRESS:
            knx_address.load(p, offset);
            break;

        case dib::Type::MFR_DATA:
            mfr_data.load(p, offset, get_dib_structure_length() - dib_header_length);
            break;

        default:
            /*FIXIT: alert */
            snort::DetectionEngine::queue_event(GID_KNXNETIP, KNXNETIP_DUMMY);
            break;
    }

}

void knxnetip::packet::dib::DeviceInfo::load(const snort::Packet& p, int& offset)
{
    util::get(knx_medium, p.data, offset, p.dsize);
    util::get(device_status, p.data, offset, p.dsize);
    util::get(knx_individual_address, p.data, offset, p.dsize);
    util::get(project_inst_id, p.data, offset, p.dsize);
    util::get(serial_number, p.data, offset, p.dsize, ser_num_size);
    util::get(multicast_address, p.data, offset, p.dsize);
    util::get(mac_address, p.data, offset, p.dsize, mac_adr_size);
    util::get(device_friendly_name, p.data, offset, p.dsize, dev_nam_size);
}

void knxnetip::packet::dib::SuppSvcFamily::load(const snort::Packet& p, int& offset, uint8_t structure_length)
{
    util::get(id, p.data, offset, p.dsize);
    util::get(version, p.data, offset, p.dsize);

    size = structure_length/2;
    offset += (size * 2) - sizeof(*id) - sizeof(*version);
}

void knxnetip::packet::dib::IpConfig::load(const snort::Packet& p, int& offset)
{
    util::get(ip, p.data, offset, p.dsize);
    util::get(subnet, p.data, offset, p.dsize);
    util::get(gateway, p.data, offset, p.dsize);
    util::get(capabilities, p.data, offset, p.dsize);
    util::get(assignment_method, p.data, offset, p.dsize);
}

void knxnetip::packet::dib::IpCurrent::load(const snort::Packet& p, int& offset)
{
    util::get(ip, p.data, offset, p.dsize);
    util::get(subnet, p.data, offset, p.dsize);
    util::get(gateway, p.data, offset, p.dsize);
    util::get(dhcp, p.data, offset, p.dsize);
    util::get(assignment_method, p.data, offset, p.dsize);
    util::get(reserved, p.data, offset, p.dsize); /* call for correct offset tracking */
}

void knxnetip::packet::dib::KnxAddress::load(const snort::Packet& p, int& offset)
{
    util::get(address, p.data, offset, p.dsize);
}

void knxnetip::packet::dib::MfrData::load(const snort::Packet& p, int& offset, uint8_t structure_length)
{
    size = structure_length - sizeof(*manufacturer_id);

    util::get(manufacturer_id, p.data, offset, p.dsize);
    util::get(manufacturer_data, p.data, offset, size, p.dsize);
}

/* CR */
void knxnetip::packet::cr::CR::load(const snort::Packet& p, int& offset)
{
    util::get(structure_length, p.data, offset, p.dsize);
    util::get(connection_type_code, p.data, offset, p.dsize);
}

void knxnetip::packet::CRI::load(const snort::Packet& p, int& offset)
{
    CR::load(p, offset);

    if (get_structure_length() != (p.dsize - offset + 2))
    {
        /*FIXME: alert */
        snort::DetectionEngine::queue_event(GID_KNXNETIP, KNXNETIP_DUMMY);
    }

    switch(get_connection_type_code())
    {
        case cr::ConnType::DEVICE_MGMT_CONNECTION:
            if (get_structure_length() != 2)
            {
                /*FIXME: alert */
                snort::DetectionEngine::queue_event(GID_KNXNETIP, KNXNETIP_DUMMY);
            }
            break;

        case cr::ConnType::TUNNEL_CONNECTION:
            if (get_structure_length() != 4)
            {
                /*FIXME: alert */
                snort::DetectionEngine::queue_event(GID_KNXNETIP, KNXNETIP_DUMMY);
            }
            util::get(knx_layer, p.data, offset, p.dsize);
            util::get(reserved, p.data, offset, p.dsize); /* call for correct offset tracking */
            break;

        default:
            /*FIXME: alert */
            snort::DetectionEngine::queue_event(GID_KNXNETIP, KNXNETIP_DUMMY);
            break;
    }
}

void knxnetip::packet::CRD::load(const snort::Packet& p, int& offset)
{
    CR::load(p, offset);

    if (get_structure_length() != (p.dsize - offset + 2))
    {
        /*FIXME: alert */
        snort::DetectionEngine::queue_event(GID_KNXNETIP, KNXNETIP_DUMMY);
    }

    switch(get_connection_type_code())
    {
        case cr::ConnType::DEVICE_MGMT_CONNECTION:
            if (get_structure_length() != 2)
            {
                /*FIXME: alert */
                snort::DetectionEngine::queue_event(GID_KNXNETIP, KNXNETIP_DUMMY);
            }
            break;

        case cr::ConnType::TUNNEL_CONNECTION:
            if (get_structure_length() != 4)
            {
                /*FIXME: alert */
                snort::DetectionEngine::queue_event(GID_KNXNETIP, KNXNETIP_DUMMY);
            }
            util::get(knx_address, p.data, offset, p.dsize);
            break;

        default:
            /*FIXME: alert */
            snort::DetectionEngine::queue_event(GID_KNXNETIP, KNXNETIP_DUMMY);
            break;
    }
}

/* Connection Header */
void knxnetip::packet::ConnectionHeader::load(const snort::Packet& p, int& offset)
{
    util::get(structure_length, p.data, offset, p.dsize);
    util::get(communication_channel_id, p.data, offset, p.dsize);
    util::get(sequence_counter, p.data, offset, p.dsize);
    util::get(status, p.data, offset, p.dsize);
}

/* SELECTOR */
void knxnetip::packet::SELECTOR::load(const snort::Packet& p, int& offset)
{
    util::get(structure_length, p.data, offset, p.dsize);
    util::get(selector_type_code, p.data, offset, p.dsize);

    switch(get_selector_type_code())
    {
        case SELECTOR::Type::PrgMode:
            break;

        case SELECTOR::Type::MAC:
            util::get(mac_address, p.data, offset, p.dsize, mac_adr_size);
            break;

        default:
            /*FIXME: alert */
            snort::DetectionEngine::queue_event(GID_KNXNETIP, KNXNETIP_DUMMY);
            break;
    }
}
