#pragma once

#include "./ngc.hpp"

#include <solanaceae/contact/contact_model3.hpp>
#include <solanaceae/message3/registry_message_model.hpp>

#include <array>
#include <queue>
#include <map>
#include <random>

// fwd
struct ToxI;
struct ContactModelI;
class ToxContactModel2;

// zoff ngc history sync (draft1?)
// https://gist.github.com/zoff99/81917ddb2e55b2ce602cac4772a7b68c

class ZoxNGCHistorySync : public ToxEventI, public ZoxNGCEventI {
	ToxEventProviderI& _tep;
	ZoxNGCEventProviderI& _zngcepi;
	ToxI& _t;
	Contact3Registry& _cr;
	ToxContactModel2& _tcm;
	RegistryMessageModelI& _rmm;

	// how far apart the 2 timestamps can be, before they are considered different messages
	const int64_t _max_age_difference_ms {130*60*1000}; // TODO: make this larger?

	// 5s-11s
	const float _delay_before_first_request_min {5.f};
	const float _delay_before_first_request_add {6.f};

	// 30m-64m
	const float _delay_next_request_min {30.f*60.f};
	const float _delay_next_request_add {64.f*60.f};

	// 0.3s-0.6s
	const float _delay_between_syncs_min {0.3f};
	const float _delay_between_syncs_add {0.3f};

	std::uniform_real_distribution<float> _rng_dist {0.0f, 1.0f};
	std::minstd_rand _rng;

	struct RequestQueueInfo {
		float delay; // const
		float timer;
		uint8_t sync_delta;
	};
	// request queue
	// c -> delay, timer
	std::map<Contact3, RequestQueueInfo> _request_queue;

	struct SyncQueueInfo {
		float delay; // const
		float timer;
		std::queue<Message3> ents;
		//std::reference_wrapper<Message1Registry> reg;
	};
	std::map<Contact3, SyncQueueInfo> _sync_queue;

	// sync queue

	void subscribeToEvents(void); // private

	public:
		ZoxNGCHistorySync(ToxEventProviderI& tep, ZoxNGCEventProviderI& zngcepi, ToxI& t, Contact3Registry& cr, ToxContactModel2& tcm, RegistryMessageModelI& rmm);

		float tick(float delta);

	public:
		// always private
		bool sendRequest(
			uint32_t group_number, uint32_t peer_number,
			uint8_t sync_delta = 130u
		);

		// always private
		bool sendSyncMessage(
			uint32_t group_number, uint32_t peer_number,
			uint32_t message_id,
			const std::array<uint8_t, 32>& sender_pub_key,
			uint32_t timestamp,
			std::string_view sender_name,
			std::string_view message_text
		);

	protected:
		bool onEvent(const Events::ZoxNGC_ngch_request& e) override;
		bool onEvent(const Events::ZoxNGC_ngch_syncmsg& e) override;

	protected:
		bool onToxEvent(const Tox_Event_Group_Peer_Join* e) override;
		//bool onToxEvent(const Tox_Event_Group_Peer_Exit* e) override;
		//bool onToxEvent(const Tox_Event_Group_Custom_Packet* e) override;
		//bool onToxEvent(const Tox_Event_Group_Custom_Private_Packet* e) override;
};

