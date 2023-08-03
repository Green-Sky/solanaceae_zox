cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(solanaceae)

add_library(solanaceae_zox
	./solanaceae/zox/ngc.hpp
	./solanaceae/zox/ngc.cpp

	./solanaceae/zox/ngc_hs.hpp
	./solanaceae/zox/ngc_hs.cpp
)

target_include_directories(solanaceae_zox PUBLIC .)
target_compile_features(solanaceae_zox PUBLIC cxx_std_17)
target_link_libraries(solanaceae_zox PUBLIC
	solanaceae_util
	solanaceae_message3
	solanaceae_toxcore
	solanaceae_tox_contacts
	solanaceae_tox_messages
)

