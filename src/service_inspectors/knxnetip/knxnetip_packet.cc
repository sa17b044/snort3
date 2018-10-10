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
// knxnetip_packet.cc author Alija Sabic <sabic@technikum-wien.at>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <utility>
#include "detection/detection_engine.h"
#include "knxnetip_module.h"
#include "knxnetip_packet.h"
#include "knxnetip_tables.h"
#include "knxnetip_detect.h"

using knxnetip::module::server;
using knxnetip::module::policy;

bool knxnetip::Packet::dissect(const snort::Packet& p, const server& server, const policy& policy)
{
    using knxnetip::packet::Header;
    using knxnetip::ServiceType;

    /* Lay the header struct over the payload */
    h = (const Header*)p.data;
    int offset = knxnetip::HEADER_SIZE;

    if (h->get_length() != knxnetip::HEADER_SIZE)
    {
        knxnetip::queue_event(KNXNETIP_HEAD_SIZE, p, server, policy);
        return false;
    }
    if (h->get_total_length() != p.dsize)
    {
        knxnetip::queue_event(KNXNETIP_TOTAL_LEN, p, server, policy);
        return false;
    }

    if (h->get_version() == knxnetip::KNXNETIP_VERSION_10)
    {

        /* Load KNXnet/IP service */
        switch(h->get_service_type())
        {
            /* KNXnet/IP Core */
            case ServiceType::SEARCH_REQ:
                search_request.load(p, offset, server, policy);
                break;

            case ServiceType::SEARCH_RES:
                search_response.load(p, offset, server, policy);
                break;

            case ServiceType::DESCRIPTION_REQ:
                description_request.load(p, offset, server, policy);
                break;

            case ServiceType::DESCRIPTION_RES:
                description_response.load(p, offset, h->get_body_length(), server, policy);
                break;

            case ServiceType::CONNECT_REQ:
                connect_request.load(p, offset, server, policy);
                break;

            case ServiceType::CONNECT_RES:
                connect_response.load(p, offset, server, policy);
                break;

            case ServiceType::CONNECTIONSTATE_REQ:
                connection_state_request.load(p, offset, server, policy);
                break;

            case ServiceType::CONNECTIONSTATE_RES:
                connection_state_response.load(p, offset);
                break;

            case ServiceType::DISCONNECT_REQ:
                disconnect_request.load(p, offset, server, policy);
                break;

            case ServiceType::DISCONNECT_RES:
                disconnect_response.load(p, offset);
                break;

            /* KNXnet/IP Device Management */
            case ServiceType::DEVICE_CONFIGURATION_REQ:
                device_conf_request.load(p, offset, h->get_body_length(), server, policy);
                break;

            case ServiceType::DEVICE_CONFIGURATION_ACK:
                device_conf_acknowledge.load(p, offset);
                break;

            /* KNXnet/IP Tunnelling */
            case ServiceType::TUNNELLING_REQ:
                tunnelling_request.load(p, offset, h->get_body_length(), server, policy);
                break;

            case ServiceType::TUNNELLING_ACK:
                tunnelling_acknowledge.load(p, offset);
                break;

            /* KNXnet/IP Routing */
            case ServiceType::ROUTING_INDICATION:
                routing_indication.load(p, offset, h->get_body_length(), server, policy);
                break;

            case ServiceType::ROUTING_LOST:
                routing_lost.load(p, offset);
                break;

            case ServiceType::ROUTING_BUSY:
                routing_busy.load(p, offset);
                break;

            /* KNXnet/IP Remote Diagnosis and Configuration */
            case ServiceType::REMOTE_DIAG_REQ:
                rem_diag_request.load(p, offset, server, policy);
                break;

            case ServiceType::REMOTE_DIAG_RES:
                rem_diag_response.load(p, offset, h->get_body_length());
                break;

            case ServiceType::REMOTE_BASIC_CONF_REQ:
                rem_basic_conf_request.load(p, offset, server, policy, h->get_body_length());
                break;

            case ServiceType::REMOTE_RESET_REQ:
                rem_reset_request.load(p, offset, server, policy);
                break;

            default:
                knxnetip::queue_event(KNXNETIP_SRVC_TYPE, p, server, policy);
                return false;
        }

    }
    else if (h->get_version() == knxnetip::KNXNETIP_VERSION_13)
    {
        /* Load KNXnet/IP service */
        switch(h->get_service_type())
        {
            /* KNXnet/IP Secure */
            case ServiceType::SECURE_WRAPPER:
                sec_wrapper.load(p, offset);
                break;

            case ServiceType::SECURE_CHANNEL_REQ:
                sec_chan_request.load(p, offset, server, policy);
                break;

            case ServiceType::SECURE_CHANNEL_RES:
                sec_chan_response.load(p, offset);
                break;

            case ServiceType::SECURE_CHANNEL_AUTH:
                sec_chan_authorize.load(p, offset);
                break;

            case ServiceType::SECURE_CHANNEL_STAT:
                sec_chan_status.load(p, offset, server, policy);
                break;

            case ServiceType::SECURE_GROUP_SYNC_REQ:
                sec_group_sync_request.load(p, offset);
                break;

            case ServiceType::SECURE_GROUP_SYNC_RES:
                sec_group_sync_response.load(p, offset);
                break;

            default:
                knxnetip::queue_event(KNXNETIP_SRVC_TYPE, p, server, policy);
                return false;
        }
    }
    else
    {
        knxnetip::queue_event(KNXNETIP_PROT_VERS, p, server, policy);
        return false;
    }

    if (p.dsize != offset)
    {
        knxnetip::queue_event(KNXNETIP_TOTAL_LEN, p, server, policy);
        return false;
    }

    return true;
}

void knxnetip::packet::SearchRequest::load(const snort::Packet& p, int& offset, const server& server, const policy& policy)
{
    discovery_endpoint.load(p, offset, server, policy);
}

void knxnetip::packet::SearchResponse::load(const snort::Packet& p, int& offset, const server& server, const policy& policy)
{
    control_endpoint.load(p, offset, server, policy);
    device_hardware.load(p, offset, server, policy);
    supported_service_families.load(p, offset, server, policy);
}

void knxnetip::packet::DescriptionRequest::load(const snort::Packet& p, int& offset, const server& server, const policy& policy)
{
    control_endpoint.load(p, offset, server, policy);
}

void knxnetip::packet::DescriptionResponse::load(const snort::Packet& p, int& offset, int body_length, const server& server, const policy& policy)
{
    int current_offset = offset;
    device_hardware.load(p, offset, server, policy);
    supported_service_families.load(p, offset, server, policy);

    if (body_length > (offset - current_offset))
    {
        additional_dib_length = body_length - (offset - current_offset);
        knxnetip::util::get(additional_dibs, p.data, offset, p.dsize, additional_dib_length);
    }
    else
    {
        additional_dib_length = 0;
    }
}

knxnetip::packet::DIB knxnetip::packet::DescriptionResponse::get_add_dib(int i) const
{
    knxnetip::packet::DIB r{};

    if ((additional_dib_length == 0) or (i < 0))
    {
        return r;
    }

    snort::Packet p;
    p.data = additional_dibs;
    p.dsize = 0;
    int offset = 0;

    int j;
    for (j = 0; offset < additional_dib_length and j + 1 != i; j++) {
        r.load(p, offset);
    }

    /* Requested dib number to high */
    if (j + 1 != i)
    {
        r = knxnetip::packet::DIB{};
    }

    return r;
}

void knxnetip::packet::ConnectRequest::load(const snort::Packet& p, int& offset, const server& server, const policy& policy)
{
    control_endpoint.load(p, offset, server, policy);
    data_endpoint.load(p, offset, server, policy);
    connection_req_info.load(p, offset, server, policy);
}

void knxnetip::packet::ConnectResponse::load(const snort::Packet& p, int& offset, const server& server, const policy& policy)
{
    knxnetip::util::get(communication_channel_id, p.data, offset, p.dsize);
    knxnetip::util::get(connection_status, p.data, offset, p.dsize);
    data_endpoint.load(p, offset, server, policy);
    connection_res_dblock.load(p, offset, server, policy);
}

void knxnetip::packet::ConnectionStateRequest::load(const snort::Packet& p, int& offset, const server& server, const policy& policy)
{
    knxnetip::util::get(communication_channel_id, p.data, offset, p.dsize);
    knxnetip::util::get(reserved, p.data, offset, p.dsize); /* call for correct offset tracking */
    if (*reserved != 0)
    {
        knxnetip::queue_event(KNXNETIP_RESERVED_FIELD_W_DATA, p, server, policy);
    }
    control_endpoint.load(p, offset, server, policy);
}

void knxnetip::packet::ConnectionStateResponse::load(const snort::Packet& p, int& offset)
{
    knxnetip::util::get(communication_channel_id, p.data, offset, p.dsize);
    knxnetip::util::get(status, p.data, offset, p.dsize);
}

void knxnetip::packet::DisconnectRequest::load(const snort::Packet& p, int& offset, const server& server, const policy& policy)
{
    knxnetip::util::get(communication_channel_id, p.data, offset, p.dsize);
    knxnetip::util::get(reserved, p.data, offset, p.dsize); /* call for correct offset tracking */
    if (*reserved != 0)
    {
        knxnetip::queue_event(KNXNETIP_RESERVED_FIELD_W_DATA, p, server, policy);
    }
    control_endpoint.load(p, offset, server, policy);
}

void knxnetip::packet::DisconnectResponse::load(const snort::Packet& p, int& offset)
{
    knxnetip::util::get(communication_channel_id, p.data, offset, p.dsize);
    knxnetip::util::get(status, p.data, offset, p.dsize);
}

void knxnetip::packet::DeviceConfigurationRequest::load(const snort::Packet& p, int& offset, int body_length, const knxnetip::module::server& server, const knxnetip::module::policy& policy)
{
    connection_header.load(p, offset);
    cemi_frame.load(p, offset, body_length, server, policy);
}

void knxnetip::packet::DeviceConfigurationAcknowledge::load(const snort::Packet& p, int& offset)
{
    connection_header.load(p, offset);
}

void knxnetip::packet::TunnellingRequest::load(const snort::Packet& p, int& offset, int body_length, const knxnetip::module::server& server, const knxnetip::module::policy& policy)
{
    connection_header.load(p, offset);
    cemi_frame.load(p, offset, body_length, server, policy);
}

void knxnetip::packet::TunnellingAcknowledge::load(const snort::Packet& p, int& offset)
{
    connection_header.load(p, offset);
}

void knxnetip::packet::RoutingIndication::load(const snort::Packet& p, int& offset, int body_length, const knxnetip::module::server& server, const knxnetip::module::policy& policy)
{
    cemi_frame.load(p, offset, body_length, server, policy);
}

void knxnetip::packet::RoutingLost::load(const snort::Packet& p, int& offset)
{
    knxnetip::util::get(structure_length, p.data, offset, p.dsize);
    knxnetip::util::get(device_state, p.data, offset, p.dsize);
    knxnetip::util::get(number_of_lost_messages, p.data, offset, p.dsize);
}

void knxnetip::packet::RoutingBusy::load(const snort::Packet& p, int& offset)
{
    knxnetip::util::get(structure_length, p.data, offset, p.dsize);
    knxnetip::util::get(device_state, p.data, offset, p.dsize);
    knxnetip::util::get(routing_busy_wait_time, p.data, offset, p.dsize);
    knxnetip::util::get(routing_busy_control_field, p.data, offset, p.dsize);
}

void knxnetip::packet::RemoteDiagnosticRequest::load(const snort::Packet& p, int& offset, const server& server, const policy& policy)
{
    discovery_endpoint.load(p, offset, server, policy);
    selector.load(p, offset);
}

void knxnetip::packet::RemoteDiagnosticResponse::load(const snort::Packet& p, int& offset, int body_length)
{
    if (body_length > 0)
    {
        dib_length = body_length;
        knxnetip::util::get(dibs, p.data, offset, p.dsize, dib_length);
    }
    else
    {
        dib_length = 0;
    }
}

knxnetip::packet::DIB knxnetip::packet::RemoteDiagnosticResponse::get_dib(int i) const
{
    knxnetip::packet::DIB r{};

    if((dib_length == 0) or (i < 0))
    {
        return r;
    }

    snort::Packet p;
    p.data = dibs;
    p.dsize = 0;
    int offset = 0;

    int j;
    for (j = 0; offset < dib_length and j + 1 != i; j++) {
        r.load(p, offset);
    }

    /* Requested dib number to high */
    if (j + 1 != i)
    {
        r = knxnetip::packet::DIB{};
    }

    return r;
}

void knxnetip::packet::RemoteBasicConfigurationRequest::load(const snort::Packet& p, int& offset, const server& server, const policy& policy, int body_length)
{
    int current_offset = offset;
    discovery_endpoint.load(p, offset, server, policy);
    selector.load(p, offset);

    if (body_length > (offset - current_offset))
    {
        dib_length = body_length - (offset - current_offset);
        knxnetip::util::get(dibs, p.data, offset, p.dsize, dib_length);
    }
    else
    {
        dib_length = 0;
    }
}

knxnetip::packet::DIB knxnetip::packet::RemoteBasicConfigurationRequest::get_dib(int i) const
{
    knxnetip::packet::DIB r{};

    if((dib_length == 0) or (i < 0))
    {
        return r;
    }

    snort::Packet p;
    p.data = dibs;
    p.dsize = 0;
    int offset = 0;

    int j;
    for(j = 0; offset < dib_length and j + 1 != i; j++)
    {
        r.load(p, offset);
    }

    /* Requested dib number to high */
    if (j + 1 != i)
    {
        r = knxnetip::packet::DIB{};
    }

    return r;
}

void knxnetip::packet::RemoteResetRequest::load(const snort::Packet& p, int& offset, const server& server, const policy& policy)
{
    selector.load(p, offset);
    knxnetip::util::get(reset_command, p.data, offset, p.dsize);
    knxnetip::util::get(reserved, p.data, offset, p.dsize); /* call for correct offset tracking */
    if (*reserved != 0)
    {
        knxnetip::queue_event(KNXNETIP_RESERVED_FIELD_W_DATA, p, server, policy);
    }
}

void knxnetip::packet::SecureWrapper::load(const snort::Packet& p, int& offset)
{
    knxnetip::util::get(secure_channel_index, p.data, offset, p.dsize);
    knxnetip::util::get(sequence_identifier, p.data, offset, p.dsize);

    length = p.dsize - offset;
    knxnetip::util::get(encrypted_data, p.data, offset, p.dsize, length);
}

void knxnetip::packet::SecureChannelRequest::load(const snort::Packet& p, int& offset, const server& server, const policy& policy)
{
    control_endpoint.load(p, offset, server, policy);
    knxnetip::util::get(client_public_value, p.data, offset, p.dsize, pub_val_size);
}

void knxnetip::packet::SecureChannelResponse::load(const snort::Packet& p, int& offset)
{
    knxnetip::util::get(secure_channel_index, p.data, offset, p.dsize);

    if (get_secure_channel_index() != 0)
    {
        knxnetip::util::get(server_public_value, p.data, offset, p.dsize, pub_val_size);
        knxnetip::util::get(message_auth_code, p.data, offset, p.dsize, msg_aut_size);
    }
}

void knxnetip::packet::SecureChannelAuthorize::load(const snort::Packet& p, int& offset)
{
    knxnetip::util::get(authorize_context, p.data, offset, p.dsize);
    knxnetip::util::get(message_auth_code, p.data, offset, p.dsize, msg_aut_size);
}

void knxnetip::packet::SecureChannelStatus::load(const snort::Packet& p, int& offset, const server& server, const policy& policy)
{
    knxnetip::util::get(status, p.data, offset, p.dsize);
    knxnetip::util::get(reserved, p.data, offset, p.dsize); /* call for correct offset tracking */
    if (*reserved != 0)
    {
        knxnetip::queue_event(KNXNETIP_RESERVED_FIELD_W_DATA, p, server, policy);
    }
}

void knxnetip::packet::SecureGroupSyncRequest::load(const snort::Packet& p, int& offset)
{
    knxnetip::util::get(time_stamp, p.data, offset, p.dsize, time_st_size);
    knxnetip::util::get(message_auth_code, p.data, offset, p.dsize, msg_aut_size);
}

void knxnetip::packet::SecureGroupSyncResponse::load(const snort::Packet& p, int& offset)
{
    knxnetip::util::get(time_stamp, p.data, offset, p.dsize, time_st_size);
    knxnetip::util::get(message_auth_code, p.data, offset, p.dsize, msg_aut_size);
}
