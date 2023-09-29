#include "./ngc_hs.hpp"

#include <solanaceae/toxcore/tox_interface.hpp>
#include <solanaceae/contact/components.hpp>
#include <solanaceae/tox_contacts/tox_contact_model2.hpp>
#include <solanaceae/tox_contacts/components.hpp>
#include <solanaceae/message3/components.hpp>
#include <solanaceae/tox_messages/components.hpp>

#include <optional>
#include <chrono>
#include <iostream>
#include <variant>
#include <vector>

void ZoxNGCHistorySync::subscribeToEvents(void) {
	_zngcepi.subscribe(this, ZoxNGC_Event::ngch_request);
	_zngcepi.subscribe(this, ZoxNGC_Event::ngch_syncmsg);

	_tep.subscribe(this, Tox_Event::TOX_EVENT_GROUP_PEER_JOIN);
}

ZoxNGCHistorySync::ZoxNGCHistorySync(ToxEventProviderI& tep, ZoxNGCEventProviderI& zngcepi, ToxI& t, Contact3Registry& cr, ToxContactModel2& tcm, RegistryMessageModel& rmm)
	: _tep(tep), _zngcepi(zngcepi), _t(t), _cr(cr), _tcm(tcm), _rmm(rmm), _rng(std::random_device{}())
{
	subscribeToEvents();
}

void ZoxNGCHistorySync::tick(float delta) {
	// send queued requests
	for (auto it = _request_queue.begin(); it != _request_queue.end();) {
		it->second.timer += delta;

		if (it->second.timer >= it->second.delay) {
			if (!_cr.all_of<Contact::Components::ToxGroupPeerEphemeral>(it->first)) {
				// peer nolonger online
				it = _request_queue.erase(it);
				continue;
			}
			const auto [group_number, peer_number] = _cr.get<Contact::Components::ToxGroupPeerEphemeral>(it->first);

			if (sendRequest(group_number, peer_number, it->second.sync_delta)) {
				// on success, requeue with longer delay (minutes)

				it->second.timer = 0.f;
				it->second.delay = _delay_next_request_min + _rng_dist(_rng)*_delay_next_request_add;

				// double the delay for overlap (9m-15m)
				// TODO: finetune
				it->second.sync_delta = uint8_t((it->second.delay/60.f)*2.f) + 1;

				std::cout << "ZOX #### requeued request in " << it->second.delay << "s\n";

				it++;
			} else {
				// on failure, assume disconnected
				it = _request_queue.erase(it);
			}
		} else {
			it++;
		}
	}

	for (auto it = _sync_queue.begin(); it != _sync_queue.end();) {
		it->second.timer += delta;
		if (it->second.timer >= it->second.delay) {
			it->second.timer = 0.f;
			Message3 msg_e = it->second.ents.front();
			it->second.ents.pop();

			if (!_cr.all_of<Contact::Components::ToxGroupPeerEphemeral>(it->first)) {
				// peer nolonger online
				it = _sync_queue.erase(it);
				continue;
			}
			const auto [group_number, peer_number] = _cr.get<Contact::Components::ToxGroupPeerEphemeral>(it->first);

			auto* reg_ptr = _rmm.get(it->first);
			if (reg_ptr == nullptr) {
				//std::cout << "°°°°°°°° no reg for contact\n";
				it = _sync_queue.erase(it);
				continue;
			}

			Message3Registry& reg = *reg_ptr;

			if (!reg.valid(msg_e)) {
				std::cerr << "ZOX NGCHS error: invalid message in sync send queue\n";
				it = _sync_queue.erase(it);
				continue;
			}

			const auto& msg_sender = reg.get<Message::Components::ContactFrom>(msg_e).c;

			if (!_cr.all_of<Contact::Components::ToxGroupPeerPersistent>(msg_sender)) {
				std::cerr << "ZOX NGCHS error: msg sender without persistant\n";
				continue;
			}
			//if (auto peer_persist_opt = _cm.toPersistent(msg_sender); peer_persist_opt.has_value() && std::holds_alternative<ContactGroupPeerPersistent>(peer_persist_opt.value())) {
			// get name for peer
			// TODO: make sure there is no alias leaked
			//const auto msg_sender_name = _cm.getContactName(msg_sender);
			std::string_view msg_sender_name;
			if (_cr.all_of<Contact::Components::Name>(msg_sender)) {
				msg_sender_name = _cr.get<Contact::Components::Name>(msg_sender).name;
			}


			if (!sendSyncMessage(
				group_number,
				peer_number,
				reg.get<Message::Components::ToxGroupMessageID>(msg_e).id,
				_cr.get<Contact::Components::ToxGroupPeerPersistent>(msg_sender).peer_key.data,
				std::chrono::duration_cast<std::chrono::seconds>(std::chrono::milliseconds{reg.get<Message::Components::Timestamp>(msg_e).ts}).count(),
				msg_sender_name,
				reg.get<Message::Components::MessageText>(msg_e).text
			) || it->second.ents.empty()) {
				it = _sync_queue.erase(it);
				continue;
			}
		}

		it++;
	}
}

bool ZoxNGCHistorySync::sendRequest(
	uint32_t group_number, uint32_t peer_number,
	uint8_t sync_delta
) {
	std::vector<uint8_t> packet;

	{ // magic
		//0x667788113435
		packet.push_back(0x66);
		packet.push_back(0x77);
		packet.push_back(0x88);
		packet.push_back(0x11);
		packet.push_back(0x34);
		packet.push_back(0x35);

	}

	packet.push_back(0x01); // version
	packet.push_back(0x01); // pkt_id

	packet.push_back(sync_delta);

	auto ret = _t.toxGroupSendCustomPrivatePacket(group_number, peer_number, true, packet);
	// TODO: log error

	return ret == TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_OK;
}

bool ZoxNGCHistorySync::sendSyncMessage(
	uint32_t group_number, uint32_t peer_number,
	uint32_t message_id,
	const std::array<uint8_t, 32>& sender_pub_key,
	uint32_t timestamp,
	std::string_view sender_name,
	std::string_view message_text
) {
	std::vector<uint8_t> packet;

	{ // magic
		//0x667788113435
		packet.push_back(0x66);
		packet.push_back(0x77);
		packet.push_back(0x88);
		packet.push_back(0x11);
		packet.push_back(0x34);
		packet.push_back(0x35);
	}

	packet.push_back(0x01); // version
	packet.push_back(0x02); // pkt_id

	// 4 bytes, message id
	packet.push_back(0xff & (message_id >> 8*3));
	packet.push_back(0xff & (message_id >> 8*2));
	packet.push_back(0xff & (message_id >> 8*1));
	packet.push_back(0xff & (message_id >> 8*0));

	// 32 bytes, sender pub key
	packet.insert(packet.end(), sender_pub_key.cbegin(), sender_pub_key.cend());


	// 4 bytes, timestamp
	packet.push_back(0xff & (timestamp >> 8*3));
	packet.push_back(0xff & (timestamp >> 8*2));
	packet.push_back(0xff & (timestamp >> 8*1));
	packet.push_back(0xff & (timestamp >> 8*0));


	// 25 bytes, sender name, truncated/filled with 0
	// TODO: handle unicode properly
	for (size_t i = 0; i < 25; i++) {
		if (i < sender_name.size()) {
			packet.push_back(sender_name.at(i));
		} else {
			packet.push_back('\0');
		}
	}

	// up to 39927 bytes, message
#if 0
	packet.insert(packet.end(), message_text.cbegin(), message_text.cend());
#else
	//const int64_t msg_max_possible_size = _t.toxGroup
	// TODO: make pr and add functions
	const uint64_t msg_max_possible_size = std::clamp<int64_t>(
		TOX_GROUP_MAX_CUSTOM_LOSSLESS_PACKET_LENGTH - packet.size(),
		0, // low
		39927 // high
	);

	for (size_t i = 0; i < msg_max_possible_size && i < message_text.size(); i++) {
		packet.push_back(message_text.at(i));
	}
#endif

	auto ret = _t.toxGroupSendCustomPrivatePacket(group_number, peer_number, true, packet);
	// TODO: log error

	return ret == TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_OK;
}

bool ZoxNGCHistorySync::onEvent(const Events::ZoxNGC_ngch_request& e) {
	std::cout << "ZOX ngch_request"
		<< " grp:" << e.group_number
		<< " per:" << e.peer_number
		<< " prv:" << e._private
		<< " sdl:" << (int)e.sync_delta
		<< "\n";

	// if blacklisted / on cool down

	const auto request_sender = _tcm.getContactGroupPeer(e.group_number, e.peer_number);
	if (_sync_queue.count(request_sender)) {
		std::cerr << "ZNGCHS waring: ngch_request but still in sync send queue\n";
		return true;
	}

	// const -> dont create (this is a request for existing messages)
	auto* reg_ptr = static_cast<const RegistryMessageModel&>(_rmm).get(request_sender);
	if (reg_ptr == nullptr) {
		std::cerr << "ZNGCHS error: group without reg\n";
		return true;
	}

	const Message3Registry& reg = *reg_ptr;

	std::queue<Message3> msg_send_queue;

	// convert sync delta to ms
	const int64_t sync_delta_offset_ms = int64_t(e.sync_delta) * 1000 * 60;
	const uint64_t ts_start = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count() - sync_delta_offset_ms;

	auto view = reg.view<Message::Components::ContactFrom, Message::Components::ContactTo, Message::Components::Timestamp, Message::Components::MessageText, Message::Components::ToxGroupMessageID>().use<Message::Components::Timestamp>();
	view.each([&](const Message3 e, const auto&, const auto& c_t, const auto& ts, const auto&, const auto&) {
		// private
		if (!_cr.all_of<Contact::Components::TagBig>(c_t.c)) {
			return;
		}

		if (ts.ts < ts_start) {
			std::cout << "---- " << ts.ts << " < " << ts_start << " -> too old\n";
			return;
		}
		std::cout << "---- " << ts.ts << " >= " << ts_start << " -> selected\n";

		msg_send_queue.push(e);
	});

	std::cout << "ZOX ngch_request selected " << msg_send_queue.size() << " messages\n";

	if (!msg_send_queue.empty()) {
		_sync_queue[request_sender] = SyncQueueInfo{
			_delay_between_syncs_min + _rng_dist(_rng)*_delay_between_syncs_add,
			0.f,
			std::move(msg_send_queue)
		};
	}

	return true;
}

bool ZoxNGCHistorySync::onEvent(const Events::ZoxNGC_ngch_syncmsg& e) {
	std::cout << "ZOX ngch_syncmsg"
		// who sent the syncmsg
		<< " grp:" << e.group_number
		<< " per:" << e.peer_number
		<< " prv:" << e._private

		// its contents
		<< " mid:" << e.message_id
		<< " spk:" << std::hex << (uint16_t)e.sender_pub_key[0] << (uint16_t)e.sender_pub_key[1] << std::dec
		<< " ts:" << e.timestamp
		<< " snm:" << e.sender_name
		<< " txt:" << e.message_text
		<< "\n";

	auto sync_by_c = _tcm.getContactGroupPeer(e.group_number, e.peer_number);

	assert(static_cast<bool>(sync_by_c));

	auto* reg_ptr = _rmm.get(sync_by_c);
	if (reg_ptr == nullptr) {
		std::cerr << "ZNGCHS error: group without reg\n";
		return false;
	}

	Message3Registry& reg = *reg_ptr;

	const auto sync_c = _tcm.getContactGroupPeer(e.group_number, ToxKey{e.sender_pub_key.data(), e.sender_pub_key.size()});
	assert(static_cast<bool>(sync_c)); // TODO: make conditional

	// convert to ms
	uint64_t sync_ts = std::chrono::milliseconds(std::chrono::seconds{e.timestamp}).count(); // o.o
	uint64_t now_ts = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

	// find matches
	Message3 matching_e = entt::null;
	{
		const auto view = reg.view<Message::Components::ToxGroupMessageID, Message::Components::ContactFrom, Message::Components::Timestamp>();
		for (const auto ent : view.use<Message::Components::Timestamp>()) {
			if (view.get<Message::Components::ToxGroupMessageID>(ent).id != e.message_id) {
				continue;
			}

			// how far apart the 2 timestamps can be, before they are considered different messages
			if (std::abs(int64_t(view.get<Message::Components::Timestamp>(ent).ts) - int64_t(sync_ts)) > _max_age_difference_ms) {
				std::cout << "ZOX NGCHS info: same message id, but different timestamp\n";
				continue;
			}

			const auto& ent_c = view.get<Message::Components::ContactFrom>(ent).c;
			if (!(ent_c == sync_c)) {
				std::cout << "ZOX NGCHS info: same message id, but different sender\n";
				continue;
			}

			matching_e = ent;
			break; // TODO: matching list
		}
	}

	if (reg.valid(matching_e)) {
		// TODO: do something else, like average?, trust mods more?

		const bool has_tw = reg.all_of<Message::Components::TimestampWritten>(matching_e);
		auto& msg_ts_w = reg.get_or_emplace<Message::Components::TimestampWritten>(matching_e, sync_ts);
		if (has_tw) {
			if (msg_ts_w.ts > sync_ts) {
				msg_ts_w.ts = sync_ts;
				reg.emplace_or_replace<Message::Components::Timestamp>(matching_e, sync_ts);

				// TODO: resort
				//_rmm.resort({ContactGroupEphemeral{e.group_number}});
				_rmm.throwEventUpdate(reg, matching_e);
			}
		} else {
			// TODO: actually, dont do anything?
			// TODO: resort
			//_rmm.resort({ContactGroupEphemeral{e.group_number}});
			_rmm.throwEventUpdate(reg, matching_e);
		}
	} else {
		// tmp, assume message new
		matching_e = reg.create();

		reg.emplace<Message::Components::ContactFrom>(matching_e, sync_c);
		reg.emplace<Message::Components::ContactTo>(matching_e, sync_by_c.get<Contact::Components::Parent>().parent);

		reg.emplace<Message::Components::ToxGroupMessageID>(matching_e, e.message_id);

		reg.emplace<Message::Components::MessageText>(matching_e, e.message_text);

		reg.emplace<Message::Components::TimestampProcessed>(matching_e, now_ts);
		reg.emplace<Message::Components::TimestampWritten>(matching_e, sync_ts);
		reg.emplace<Message::Components::Timestamp>(matching_e, sync_ts); // reactive?

		reg.emplace<Message::Components::TagUnread>(matching_e);

		// TODO: resort
		//_rmm.resort({ContactGroupEphemeral{e.group_number}});
		_rmm.throwEventConstruct(reg, matching_e);
	}

	{ // by whom
		auto& synced_by = reg.get_or_emplace<Message::Components::SyncedBy>(matching_e).list;
		synced_by.emplace(sync_by_c);
		// TODO: throw update?
	}

	return true;
}

bool ZoxNGCHistorySync::onToxEvent(const Tox_Event_Group_Peer_Join* e) {
	const auto group_number = tox_event_group_peer_join_get_group_number(e);
	const auto peer_number = tox_event_group_peer_join_get_peer_id(e);

	const auto c = _tcm.getContactGroupPeer(group_number, peer_number);

	if (!_request_queue.count(c)) {
		_request_queue[c] = {
			_delay_before_first_request_min + _rng_dist(_rng)*_delay_before_first_request_add,
			0.f,
			130u // TODO: magic number
		};
	}

	return false;
}

