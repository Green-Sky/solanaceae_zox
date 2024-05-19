#pragma once

#include <solanaceae/toxcore/tox_event_interface.hpp>

#include <solanaceae/util/event_provider.hpp>

#include <cstdint>
#include <array>
#include <vector>

// fwd
//struct ToxI;

// zoff ngc history sync
// https://github.com/zoff99/c-toxcore/blob/zoff99/zoxcore_local_fork/docs/ngc_group_history_sync.md
// (old) https://gist.github.com/zoff99/81917ddb2e55b2ce602cac4772a7b68c

// zoff ngc audio
// https://github.com/zoff99/c-toxcore/blob/zoff99/zoxcore_local_fork/docs/ngc_audio.md

namespace Events {

	struct ZoxNGC_ngch_request {
		uint32_t group_number {0u};
		uint32_t peer_number {0u};

		bool _private {true};

		uint8_t sync_delta {130u};
	};

	struct ZoxNGC_ngch_syncmsg {
		uint32_t group_number {0u};
		uint32_t peer_number {0u};

		bool _private {true};

		uint32_t message_id {0u};
		// TODO: span
		std::array<uint8_t, 32> sender_pub_key;
		uint32_t timestamp {0u};
		std::string_view sender_name;
		std::string_view message_text;
	};

	struct ZoxNGC_ngca {
		uint32_t group_number {0u};
		uint32_t peer_number {0u};

		bool _private {true};

		uint8_t audio_channels {1u};
		uint8_t sampling_freq {48u}; // for 48kHz
		std::vector<uint8_t> data; // 1-1362 bytes of opus encoded audio
	};

} // Events

enum class ZoxNGC_Event : uint32_t {
	// hs
	v0x01_id0x01 = 0,
	ngch_request = v0x01_id0x01,

	v0x01_id0x02,
	ngch_syncmsg = v0x01_id0x02,

	v0x01_id0x03,
	ngch_syncmsg_file = v0x01_id0x03,

	//v0x01_id0x04,
	//v0x01_id0x05,
	//v0x01_id0x06,
	//v0x01_id0x07,
	//v0x01_id0x08,
	//v0x01_id0x09,
	//v0x01_id0x0a,
	//v0x01_id0x0b,
	//v0x01_id0x0c,
	//v0x01_id0x0d,
	//v0x01_id0x0e,
	//v0x01_id0x0f,
	//v0x01_id0x10,

	v0x01_id0x11,
	ngch_ft = v0x01_id0x11,

	// ...

	v0x01_id0x31,
	ngca = v0x01_id0x31,

	// ...

	// v0x02_id0x01

	MAX
};

static_assert(size_t(ZoxNGC_Event::v0x01_id0x02) == size_t(ZoxNGC_Event::v0x01_id0x01) + 1u);

struct ZoxNGCEventI {
	using enumType = ZoxNGC_Event;
	virtual bool onEvent(const Events::ZoxNGC_ngch_request&) { return false; }
	virtual bool onEvent(const Events::ZoxNGC_ngch_syncmsg&) { return false; }
	virtual bool onEvent(const Events::ZoxNGC_ngca&) { return false; }
};

using ZoxNGCEventProviderI = EventProviderI<ZoxNGCEventI>;

class ZoxNGCEventProvider : public ToxEventI, public ZoxNGCEventProviderI {
	ToxEventProviderI& _tep;
	//ToxI& _t;

	void subscribeToEvents(void); // private

	public:
		ZoxNGCEventProvider(ToxEventProviderI& tep/*, ToxI& t*/);

	protected:
		bool onZoxGroupEvent(
			uint32_t group_number, uint32_t peer_number,
			uint8_t version, uint8_t pkt_id,
			const uint8_t* data, size_t data_size,
			bool _private
		);

		bool parse_ngch_request(
			uint32_t group_number, uint32_t peer_number,
			const uint8_t* data, size_t data_size,
			bool _private
		);

		bool parse_ngch_syncmsg(
			uint32_t group_number, uint32_t peer_number,
			const uint8_t* data, size_t data_size,
			bool _private
		);

		bool parse_ngca(
			uint32_t group_number, uint32_t peer_number,
			const uint8_t* data, size_t data_size,
			bool _private
		);

	protected:
		bool onToxEvent(const Tox_Event_Group_Custom_Packet* e) override;
		bool onToxEvent(const Tox_Event_Group_Custom_Private_Packet* e) override;
};

