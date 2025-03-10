#include <solanaceae/plugin/solana_plugin_v1.h>

#include <solanaceae/contact/contact_store_i.hpp>

#include <solanaceae/zox/ngc.hpp>
#include <solanaceae/zox/ngc_hs.hpp>
#include <solanaceae/toxcore/tox_interface.hpp>
#include <solanaceae/tox_contacts/tox_contact_model2.hpp>

#include <entt/entt.hpp>
#include <entt/fwd.hpp>

#include <memory>
#include <iostream>

static std::unique_ptr<ZoxNGCHistorySync> g_zngchs = nullptr;

constexpr const char* plugin_name = "ZoxNGCHistorySync";

extern "C" {

SOLANA_PLUGIN_EXPORT const char* solana_plugin_get_name(void) {
	return plugin_name;
}

SOLANA_PLUGIN_EXPORT uint32_t solana_plugin_get_version(void) {
	return SOLANA_PLUGIN_VERSION;
}

SOLANA_PLUGIN_EXPORT uint32_t solana_plugin_start(struct SolanaAPI* solana_api) {
	std::cout << "PLUGIN " << plugin_name << " START()\n";

	if (solana_api == nullptr) {
		return 1;
	}

	try {
		auto* tox_i = PLUG_RESOLVE_INSTANCE(ToxI);
		auto* tox_event_provider_i = PLUG_RESOLVE_INSTANCE(ToxEventProviderI);
		auto* zox_ngc_event_provider_i = PLUG_RESOLVE_INSTANCE(ZoxNGCEventProviderI);
		auto* cs = PLUG_RESOLVE_INSTANCE(ContactStore4I);
		auto* tcm = PLUG_RESOLVE_INSTANCE(ToxContactModel2);
		auto* rmm = PLUG_RESOLVE_INSTANCE(RegistryMessageModelI);

		// static store, could be anywhere tho
		// construct with fetched dependencies
		g_zngchs = std::make_unique<ZoxNGCHistorySync>(*tox_event_provider_i, *zox_ngc_event_provider_i, *tox_i, *cs, *tcm, *rmm);

		// register types
		PLUG_PROVIDE_INSTANCE(ZoxNGCHistorySync, plugin_name, g_zngchs.get());
	} catch (const ResolveException& e) {
		std::cerr << "PLUGIN " << plugin_name << " " << e.what << "\n";
		return 2;
	}

	return 0;
}

SOLANA_PLUGIN_EXPORT void solana_plugin_stop(void) {
	std::cout << "PLUGIN " << plugin_name << " STOP()\n";

	g_zngchs.reset();
}

SOLANA_PLUGIN_EXPORT float solana_plugin_tick(float delta) {
	return g_zngchs->tick(delta);
}

} // extern C

