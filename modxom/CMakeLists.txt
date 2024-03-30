
set(KERNEL_SOURCE_DIR "/lib/modules/${CMAKE_SYSTEM_VERSION}/build")

list(APPEND module_sources modxom.c modxom.h)
foreach(src ${module_sources})
  configure_file(${src} ${src} COPYONLY)
endforeach()

set(DRIVER_FILE modxom.ko)
set(KBUILD_CMD $(MAKE) -C ${KERNEL_SOURCE_DIR} modules M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR})

add_custom_command(OUTPUT ${DRIVER_FILE}
        COMMAND ${KBUILD_CMD}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        DEPENDS modxom.c VERBATIM)


add_custom_target(modxom ALL DEPENDS ${DRIVER_FILE})
add_custom_target(clean-module COMMAND make -C ${KERNEL_SOURCE_DIR} M=${CMAKE_CURRENT_BINARY_DIR} clean)
