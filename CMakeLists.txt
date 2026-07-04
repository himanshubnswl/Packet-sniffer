cmake_minimum_required(VERSION 4.0)
project(packet_sniffer)

set(CMAKE_CXX_STANDARD 20)
set(NPCAP_DIR "C:/apps/npcap-sdk-1.16")
include_directories(${NPCAP_DIR}/Include)
link_directories(${NPCAP_DIR}/Lib/x64)
add_executable(packet_sniffer main.cpp socket.cpp)
target_link_libraries(packet_sniffer wpcap Packet ws2_32)
