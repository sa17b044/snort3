//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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
// http2_data_cutter.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_data_cutter.h"

#include "service_inspectors/http_inspect/http_flow_data.h"
#include "service_inspectors/http_inspect/http_stream_splitter.h"

#include "http2_dummy_packet.h"
#include "http2_utils.h"

using namespace snort;
using namespace HttpCommon;
using namespace Http2Enums;

Http2DataCutter::Http2DataCutter(Http2FlowData* _session_data, HttpCommon::SourceId src_id) :
    session_data(_session_data),  source_id(src_id)
{ }

// Scan data frame, extract information needed for http scan.
// http scan will need the data only, stripped of padding and header.
bool Http2DataCutter::http2_scan(uint32_t length, uint32_t* flush_offset, uint32_t frame_len,
    uint8_t flags, uint32_t& data_offset)
{
    cur_data_offset = data_offset;
    cur_data = cur_padding = 0;
    if (frame_bytes_seen == 0)
    {
        frame_length = data_len = frame_len;
        padding_len = data_bytes_read = padding_read = 0;
        frame_flags = flags;
        *flush_offset = frame_bytes_seen = FRAME_HEADER_LENGTH;

        if (frame_flags & PADDED)
        {
            padding_len = session_data->padding_length[source_id];
            data_len -= (padding_len + 1);
            frame_bytes_seen += 1;
        }

        if (data_len)
            data_state = DATA;
        else if (padding_len)
            data_state = PADDING;
        else
            data_state = FULL_FRAME;
    }

    uint32_t cur_pos = data_offset + leftover_bytes + leftover_padding;
    while ((cur_pos < length) && (data_state != FULL_FRAME))
    {
        switch (data_state)
        {
        case DATA:
          {
            const uint32_t missing = data_len - data_bytes_read;
            cur_data = ((length - cur_pos) >= missing) ?
                missing : (length - cur_pos);
            data_bytes_read += cur_data;
            cur_pos += cur_data;
            if (data_bytes_read == data_len)
                data_state = padding_len ? PADDING : FULL_FRAME;
            break;
          }
        case PADDING:
          {
            const uint32_t missing = padding_len - padding_read;
            cur_padding = ((length - cur_pos) >= missing) ?
                missing : (length - cur_pos);
            cur_pos += cur_padding;
            padding_read += cur_padding;
            if (padding_read == padding_len)
                data_state = FULL_FRAME;
            break;
          }
        default:
            break;
        }
    }

    if (data_state == FULL_FRAME)
        session_data->reading_frame[source_id] = false;        

    //FIXIT-E shouldn't need both scan_remaining_frame_octets and frame_bytes_seen
    frame_bytes_seen += (cur_pos - leftover_bytes - data_offset - leftover_padding);
    *flush_offset = data_offset = cur_pos;
    session_data->scan_remaining_frame_octets[source_id] = frame_length - frame_bytes_seen;
    return true;
}

// Call http scan. After all data in first frame has been sent, set http2_end_stream flag and send
// zero-length buffer to flush through detection
StreamSplitter::Status Http2DataCutter::http_scan(const uint8_t* data, uint32_t* flush_offset)
{
    StreamSplitter::Status scan_result = StreamSplitter::SEARCH;

    if (cur_data || leftover_bytes)
    {
        uint32_t http_flush_offset = 0;
        Http2DummyPacket dummy_pkt;
        dummy_pkt.flow = session_data->flow;
        uint32_t unused = 0;
        scan_result = session_data->hi_ss[source_id]->scan(&dummy_pkt, data + cur_data_offset,
            cur_data + leftover_bytes, unused, &http_flush_offset);

        if (scan_result == StreamSplitter::FLUSH)
        {
            bytes_sent_http += http_flush_offset;
            leftover_bytes = cur_data + leftover_bytes - http_flush_offset;
            if (leftover_bytes != 0 && cur_padding != 0)
                leftover_padding = cur_padding;
            else
                leftover_padding = 0;
            *flush_offset -= leftover_bytes + leftover_padding;
        }
        else if (scan_result == StreamSplitter::SEARCH)
        {
            bytes_sent_http += (cur_data + leftover_bytes);
            leftover_bytes = leftover_padding = 0;
        }
        else if (scan_result == StreamSplitter::ABORT)
            // FIXIT-E eventually need to implement continued processing. We cannot abort just
            // because one stream went sideways. A better approach would be to put this one stream
            // into a pass through mode while continuing to process other streams. As long as we
            // can parse the framing and process most streams it is reasonable to continue.
            return StreamSplitter::ABORT;
    }
    if (data_state == FULL_FRAME)
    {
        if (leftover_bytes == 0)
        {
            // Done with this frame, cleanup
            session_data->scan_octets_seen[source_id] = 0;
            session_data->scan_remaining_frame_octets[source_id] = 0;
            session_data->scan_state[source_id] = SCAN_HEADER;
            frame_bytes_seen = 0;

            if (frame_flags & END_STREAM)
            {
                Http2Stream* const stream = session_data->find_stream(
                    session_data->current_stream[source_id]);
                bool clear_partial_buffers = false;
                if (!bytes_sent_http)
                    clear_partial_buffers = true;
                stream->finish_msg_body(source_id, false, clear_partial_buffers);

                // Since there may be multiple frame headers or zero frame headers in the flushed
                // data section, remember END_STREAM flag in the stream object
                stream->set_end_stream_on_data_flush(source_id);
                return StreamSplitter::FLUSH;
            }
            else if (scan_result != StreamSplitter::FLUSH)
                session_data->data_processing[source_id] = true;
        }
    }

    if (scan_result != StreamSplitter::FLUSH)
        *flush_offset = 0;
    return scan_result;
}

StreamSplitter::Status Http2DataCutter::scan(const uint8_t* data, uint32_t length,
    uint32_t* flush_offset, uint32_t& data_offset, uint32_t frame_len, uint8_t frame_flags)
{
    if (!http2_scan(length, flush_offset, frame_len, frame_flags, data_offset))
        return StreamSplitter::ABORT;

    session_data->stream_in_hi = session_data->current_stream[source_id];
    StreamSplitter::Status status = http_scan(data, flush_offset);
    session_data->stream_in_hi = NO_STREAM_ID;

    return status;
}

const StreamBuffer Http2DataCutter::reassemble(const uint8_t* data, unsigned len)
{
    session_data->stream_in_hi = session_data->current_stream[source_id];

    StreamBuffer frame_buf { nullptr, 0 };

    cur_data = cur_padding = cur_data_offset = 0;

    unsigned cur_pos = 0;
    while (cur_pos < len)
    {
        switch (reassemble_state)
        {
        case GET_FRAME_HDR:
          {
            if (session_data->use_leftover_hdr[source_id])
            {
                memcpy(session_data->frame_header[source_id],
                    session_data->leftover_hdr[source_id], FRAME_HEADER_LENGTH);
                reassemble_hdr_bytes_read = FRAME_HEADER_LENGTH;
                session_data->use_leftover_hdr[source_id] = false;
                cur_pos++;
            }
            else
            {
                const uint32_t missing = FRAME_HEADER_LENGTH - reassemble_hdr_bytes_read;
                const uint32_t cur_frame = ((len - cur_pos) < missing) ? (len - cur_pos) : missing;
                memcpy(session_data->frame_header[source_id] +
                    session_data->frame_header_offset[source_id] +
                    reassemble_hdr_bytes_read,
                    data + cur_pos, cur_frame);
                reassemble_hdr_bytes_read += cur_frame;

                cur_pos += cur_frame;
            }

            if (reassemble_hdr_bytes_read == FRAME_HEADER_LENGTH)
            {
                reassemble_data_len = get_frame_length(session_data->frame_header[source_id]+
                    session_data->frame_header_offset[source_id]);
                reassemble_frame_flags = get_frame_flags(session_data->frame_header[source_id]+
                    session_data->frame_header_offset[source_id]);
                cur_data_offset = cur_pos;
                session_data->frame_header_offset[source_id] += FRAME_HEADER_LENGTH;
                if (reassemble_data_len == 0)
                    reassemble_state = CLEANUP;
                else if ((reassemble_frame_flags & PADDED) !=0)
                    reassemble_state = GET_PADDING_LEN;
                else
                    reassemble_state = SEND_DATA;
            }

            break;
          }
        case GET_PADDING_LEN:
            reassemble_padding_len = *(data + cur_pos);
            reassemble_data_len -= (reassemble_padding_len + 1);
            cur_pos++;
            cur_data_offset++;
            if (reassemble_data_len)
                reassemble_state = SEND_DATA;
            else if (reassemble_padding_len)
                reassemble_state = SKIP_PADDING;
            else
                reassemble_state = CLEANUP;
            break;
        case SEND_DATA:
          {
            const uint32_t missing = reassemble_data_len - reassemble_data_bytes_read;
            cur_data = ((len - cur_pos) >= missing) ? missing : (len - cur_pos);
            reassemble_data_bytes_read += cur_data;
            cur_pos += cur_data;

            unsigned copied;
            uint32_t flags = (bytes_sent_http == (cur_data + reassemble_bytes_sent)) ?
                PKT_PDU_TAIL : 0;
            frame_buf = session_data->hi_ss[source_id]->reassemble(session_data->flow,
                bytes_sent_http, 0, data + cur_data_offset, cur_data,
                flags, copied);
            assert(copied == (unsigned)cur_data);
            reassemble_bytes_sent += copied;

            if (reassemble_data_bytes_read == reassemble_data_len)
                reassemble_state = (reassemble_padding_len) ? SKIP_PADDING : CLEANUP;

            break;
          }
        case SKIP_PADDING:
          {
            const uint32_t missing = reassemble_padding_len - reassemble_padding_read;
            cur_padding = ((len - cur_pos) >= missing) ?
                missing : (len - cur_pos);
            cur_pos += cur_padding;
            reassemble_padding_read += cur_padding;

            if (reassemble_padding_read == reassemble_padding_len)
                reassemble_state = CLEANUP;

            break;
          }
        default:
            break;
        }

        if (reassemble_state == CLEANUP)
        {
            Http2Stream* const stream = session_data->find_stream(
                session_data->current_stream[source_id]);
            if (bytes_sent_http == 0 && (reassemble_frame_flags & END_STREAM) &&
                stream->is_partial_buf_pending(source_id))
            {
                // Received end of stream without new data. Flush pending partial buffer.
                assert(frame_buf.data == nullptr);
                unsigned unused;
                frame_buf = session_data->hi_ss[source_id]->reassemble(session_data->flow,
                    0, 0, nullptr, 0, PKT_PDU_TAIL, unused);
            }

            // Done with this packet, cleanup
            reassemble_state = GET_FRAME_HDR;
            reassemble_hdr_bytes_read = reassemble_data_bytes_read = reassemble_padding_read =
                        reassemble_padding_len = 0;
        }
    }

    if (frame_buf.data != nullptr)
    {
        session_data->frame_data[source_id] = const_cast <uint8_t*>(frame_buf.data);
        session_data->frame_data_size[source_id] = frame_buf.length;
        bytes_sent_http = reassemble_bytes_sent = 0;
    }

    session_data->stream_in_hi = NO_STREAM_ID;

    return frame_buf;
}
