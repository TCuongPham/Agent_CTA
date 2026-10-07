cmake_minimum_required(VERSION 3.16)
project(SysMon VERSION 1.0.0 LANGUAGES CXX)

# Tiêu chuẩn C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Mặc định cấu hình Debug nếu không chỉ định (để tự động sinh cờ -g cho GDB)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Chọn kiểu build (Debug hoặc Release)" FORCE)
endif()

# Thư mục include chung
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)

# -------------------------------------------------------------
# 1. CTB (Controller / Server & Logger) - Hoạt động trên cả Linux & Windows
# -------------------------------------------------------------
set(CTB_SOURCES
    src_CTB/main_ctb.cpp
    src_CTB/CTB.cpp
    include/ISocketChannel.cpp
)

add_executable(CTB ${CTB_SOURCES})

if(WIN32)
    target_link_libraries(CTB PRIVATE ws2_32)
elseif(UNIX)
    target_link_libraries(CTB PRIVATE pthread)
endif()

# -------------------------------------------------------------
# 2. CTA (Monitoring Agent / Client)
# -------------------------------------------------------------
set(CTA_COMMON_SOURCES
    src_CTA/main_cta.cpp
    src_CTA/CTA.cpp
    src_CTA/EventQueue.cpp
    include/ISocketChannel.cpp
)

if(WIN32)
    # Nền tảng Windows
    file(GLOB CTA_WIN_SOURCES
        "src_CTA/window/*.cpp"
        "src_CTA/windows/*.cpp"
    )

    set(CTA_WIN_SOURCES
        src_CTA/WFPNetTracker.cpp
        src_CTA/windows/WindowsProcessMonitor.cpp
        src_CTA/windows/WindowsRegistryStorage.cpp
    )
    
    if(CTA_WIN_SOURCES)
        add_executable(CTA ${CTA_COMMON_SOURCES} ${CTA_WIN_SOURCES})
        target_include_directories(CTA PRIVATE 
            ${CMAKE_CURRENT_SOURCE_DIR}/src_CTA/window 
            ${CMAKE_CURRENT_SOURCE_DIR}/src_CTA/windows
        )
        target_link_libraries(CTA PRIVATE ws2_32 psapi pdh iphlpapi)
    else()
        message(STATUS "[CTA] Chưa phát hiện file nguồn Windows trong src_CTA/window. Tạm thời chỉ build CTB trên Windows.")
    endif()

elseif(UNIX)
    # Nền tảng Linux
    set(CTA_LINUX_SOURCES
        src_CTA/BPFNetTracker.cpp
        src_CTA/linux/LinuxProcessMonitor.cpp
        src_CTA/linux/LinuxFileStorage.cpp
    )
    add_executable(CTA ${CTA_COMMON_SOURCES} ${CTA_LINUX_SOURCES})
    target_include_directories(CTA PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/src_CTA 
        ${CMAKE_CURRENT_SOURCE_DIR}/src_CTA/linux
    )
    target_link_libraries(CTA PRIVATE pthread bpf)
endif()
