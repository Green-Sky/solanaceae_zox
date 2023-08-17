#include "./ngc.hpp"

#include <optional>
#include <tuple>
#include <iostream>

constexpr size_t zox_magic_size = 6;
static bool is_zox_magic(const uint8_t* data, size_t size) {
	//0x667788113435
	return size >= zox_magic_size &&
		data != nullptr &&
		data[0] == 0x66 &&
		data[1] == 0x77 &&
		data[2] == 0x88 &&
		data[3] == 0x11 &&
		data[4] == 0x34 &&
		data[5] == 0x35;
}

constexpr size_t zox_header_size = zox_magic_size + 2;
std::optional<std::pair<uint8_t, uint8_t>> parse_zox_pkg_header(const uint8_t* data, size_t size) {
	if (!is_zox_magic(data, size)) {
		return std::nullopt;
	}

	data += zox_magic_size;
	size -= zox_magic_size;

	if (size < 2) {
		return std::nullopt;
	}

	const uint8_t version = data[0];
	const uint8_t pkt_id = data[1];

	return std::make_pair(version, pkt_id);
}

void ZoxNGCEventProvider::subscribeToEvents(void) {
	_tep.subscribe(this, Tox_Event::TOX_EVENT_GROUP_CUSTOM_PACKET);
	_tep.subscribe(this, Tox_Event::TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET);
}

ZoxNGCEventProvider::ZoxNGCEventProvider(ToxEventProviderI& tep) : _tep(tep) {
	subscribeToEvents();
}

bool ZoxNGCEventProvider::onZoxGroupEvent(
	uint32_t group_number, uint32_t peer_number,
	uint8_t version, uint8_t pkt_id,
	const uint8_t* data, size_t data_size,
	bool _private
) {
	if (version == 0x01 && pkt_id == 0x01) {
		// ngch_request
		return parse_ngch_request(group_number, peer_number, data, data_size, _private);
	} else if (version == 0x01 && pkt_id == 0x02) {
		// ngch_syncmsg
		return parse_ngch_syncmsg(group_number, peer_number, data, data_size, _private);
	} else if (version == 0x01 && pkt_id == 0x03) {
		std::cout << "ZOX waring: ngch_syncmsg_file not implemented\n";
	} else if (version == 0x01 && pkt_id == 0x11) {
		std::cout << "ZOX waring: ngc_ft not implemented\n";
	} else {
		std::cout << "ZOX waring: unknown packet v"
			<< (int)version
			<< " id" << (int)pkt_id
			<< " s:" << data_size
			<< "\n";
	}

	return false;
}

bool ZoxNGCEventProvider::parse_ngch_request(
	uint32_t group_number, uint32_t peer_number,
	const uint8_t* data, size_t data_size,
	bool _private
) {
	if (data_size > 1) {
		std::cerr << "ZOX ngch_request has wrong size, should: <=1 , is: " << data_size << "\n";
		return false;
	}

	uint8_t sync_delta = 130u;
	if (data_size == 1) {
		sync_delta = data[0];

		// clamp
		if (sync_delta < 5u) {
			sync_delta = 5u;
		} else if (sync_delta > 130u) {
			sync_delta = 130u;
		}
	}

	return dispatch(
		ZoxNGC_Event::ngch_request,
		Events::ZoxNGC_ngch_request{
			group_number,
			peer_number,
			_private,
			sync_delta
		}
	);
}

bool ZoxNGCEventProvider::parse_ngch_syncmsg(
	uint32_t group_number, uint32_t peer_number,
	const uint8_t* data, size_t data_size,
	bool _private
) {

	constexpr size_t min_pkg_size = 4 + 32 + 4 + 25;
	if (data_size <= 4 + 32 + 4 + 25) {
		std::cerr << "ZOX ngch_syncmsg has wrong size, should: >=" << min_pkg_size << " , is: " << data_size << "\n";
		return false;
	}

	// 4 bytes, message id
	uint32_t message_id = 0;
	message_id |= uint32_t(data[0]) << 8*3;
	message_id |= uint32_t(data[1]) << 8*2;
	message_id |= uint32_t(data[2]) << 8*1;
	message_id |= uint32_t(data[3]) << 8*0;

	data += 4;
	data_size -= 4;

	// 32 bytes, sender pub key
	std::array<uint8_t, 32> sender_pub_key {
		data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
		data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
		data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
		data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
	};

	data += 32;
	data_size -= 32;

	// 4 bytes, timestamp
	uint32_t timestamp = 0;
	timestamp |= uint32_t(data[0]) << 8*3;
	timestamp |= uint32_t(data[1]) << 8*2;
	timestamp |= uint32_t(data[2]) << 8*1;
	timestamp |= uint32_t(data[3]) << 8*0;

	data += 4;
	data_size -= 4;

	// 25 bytes, sender name, truncated/filled with 0
	std::string_view sender_name{reinterpret_cast<const char*>(data), 25};
	sender_name = sender_name.substr(0, sender_name.find_first_of('\0')); // trim \0

	data += 25;
	data_size -= 25;

	// up to 39927 bytes, message
	std::string_view message_text{reinterpret_cast<const char*>(data), data_size};
	message_text = message_text.substr(0, message_text.find_first_of('\0')); // trim \0

	return dispatch(
		ZoxNGC_Event::ngch_syncmsg,
		Events::ZoxNGC_ngch_syncmsg{
			group_number,
			peer_number,
			_private,
			message_id,
			sender_pub_key,
			timestamp,
			sender_name,
			message_text
		}
	);
}

bool ZoxNGCEventProvider::onToxEvent(const Tox_Event_Group_Custom_Packet* e) {
	const uint32_t group_number = tox_event_group_custom_packet_get_group_number(e);
	const uint32_t peer_number = tox_event_group_custom_packet_get_peer_id(e);
	const uint8_t* data = tox_event_group_custom_packet_get_data(e);
	size_t size = tox_event_group_custom_packet_get_data_length(e);

	auto res_opt = parse_zox_pkg_header(data, size);
	if (!res_opt) {
		return false;
	}

	auto [version, pkt_id] = *res_opt;

	data += zox_header_size;
	size -= zox_header_size;

	return onZoxGroupEvent(
		group_number, peer_number,
		version, pkt_id,
		data, size,
		false
	);
}

bool ZoxNGCEventProvider::onToxEvent(const Tox_Event_Group_Custom_Private_Packet* e) {
	const uint32_t group_number = tox_event_group_custom_private_packet_get_group_number(e);
	const uint32_t peer_number = tox_event_group_custom_private_packet_get_peer_id(e);
	const uint8_t* data = tox_event_group_custom_private_packet_get_data(e);
	size_t size = tox_event_group_custom_private_packet_get_data_length(e);

	auto res_opt = parse_zox_pkg_header(data, size);
	if (!res_opt) {
		return false;
	}

	auto [version, pkt_id] = *res_opt;

	data += zox_header_size;
	size -= zox_header_size;

	return onZoxGroupEvent(
		group_number, peer_number,
		version, pkt_id,
		data, size,
		true
	);
}

