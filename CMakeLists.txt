cmake_minimum_required(VERSION 4.0)
project(packet_sniffer)

set(CMAKE_CXX_STANDARD 20)
set(NPCAP_DIR "C:/apps/npcap-sdk-1.16")

find_package(Qt6 REQUIRED COMPONENTS Widgets)

qt_standard_project_setup()

include_directories(${NPCAP_DIR}/Include)
link_directories(${NPCAP_DIR}/Lib/x64)

##change the way i add paths in the source varaible
set(Sources src/window.cpp src/mymodel.cpp src/socket.cpp)

qt_add_executable(gui ${Sources})
target_link_libraries(gui PRIVATE Qt6::Widgets wpcap Packet ws2_32)

set_target_properties(gui PROPERTIES
        MACOSX_BUNDLE TRUE
        WIN32_EXECUTABLE TRUE
)

install(TARGETS gui
        BUNDLE DESTINATION .
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
