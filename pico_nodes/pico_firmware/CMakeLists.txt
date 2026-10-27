cmake_minimum_required(VERSION 3.13)

# Include Pico SDK
include(pico_sdk_import.cmake OPTIONAL)

project(trustedge_pico2 C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Target Raspberry Pi Pico 2 (RP2350 with ARM Cortex-M33 TrustZone)
set(PICO_BOARD pico2)

if (COMMAND pico_sdk_init)
    pico_sdk_init()

    add_executable(trustedge_pico
        non_secure/main.c
    )

    target_link_libraries(trustedge_pico
        pico_stdlib
        hardware_gpio
    )

    pico_enable_stdio_usb(trustedge_pico 1)
    pico_enable_stdio_uart(trustedge_pico 0)
    pico_add_extra_outputs(trustedge_pico)
endif()
