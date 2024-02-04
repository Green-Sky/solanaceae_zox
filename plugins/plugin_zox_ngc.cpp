#include <solanaceae/plugin/solana_plugin_v1.h>

#include <solanaceae/zox/ngc.hpp>

#include <memory>
#include <limits>
#include <iostream>

static std::unique_ptr<ZoxNGCEventProvider> g_zngc = nullptr;

constexpr const char* plugin_name = "ZoxNGC";

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
		auto* tox_event_provider_i = PLUG_RESOLVE_INSTANCE(ToxEventProviderI);

		// static store, could be anywhere tho
		// construct with fetched dependencies
		g_zngc = std::make_unique<ZoxNGCEventProvider>(*tox_event_provider_i);

		// register types
		PLUG_PROVIDE_INSTANCE(ZoxNGCEventProviderI, plugin_name, g_zngc.get());
	} catch (const ResolveException& e) {
		std::cerr << "PLUGIN " << plugin_name << " " << e.what << "\n";
		return 2;
	}

	return 0;
}

SOLANA_PLUGIN_EXPORT void solana_plugin_stop(void) {
	std::cout << "PLUGIN " << plugin_name << " STOP()\n";

	g_zngc.reset();
}

SOLANA_PLUGIN_EXPORT float solana_plugin_tick(float delta) {
	(void)delta;
	return std::numeric_limits<float>::max();
}

} // extern C

