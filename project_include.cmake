# esptool_merge_bin
#
# esptool.py --chip ESP32 merge_bin -o merged-flash.bin @flash_args
#
# The merge_bin command will merge multiple binary files (of any kind) into a single file that can be flashed to a device later. 
# Any gaps between the input files are padded based on the selected output format.
# flashed using `idf.py flash`
function(esptool_merge_bin out_name)
    idf_build_get_property(idf_path IDF_PATH)
    set(esptool_py ${PYTHON} ${idf_path}/components/esptool_py/esptool/esptool.py)

    set(image_name ${out_name}.bin)

    # Execute esptool merge_bin command; this always executes as there is no way to specify for CMake to watch for
    # contents of the base dir changing.
    add_custom_target(${CMAKE_PROJECT_NAME}_merged_bin ALL
        DEPENDS app #gen_project_binary
        COMMAND ${esptool_py} --chip ${CONFIG_IDF_TARGET} merge_bin -o ${image_name} @flash_args
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Generating merged binary image: ${image_name}"
        )
    #add_dependencies(app ${CMAKE_PROJECT_NAME}_merged_bin)
endfunction()

function(esptool_package_firmware new_name)
    add_custom_target(${CMAKE_PROJECT_NAME}_firmware_bin ALL
        DEPENDS app #gen_project_binary
        COMMAND "${CMAKE_COMMAND}" -E copy "${CMAKE_PROJECT_NAME}.bin" "${new_name}.bin"
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Package firmware binary to: ${new_name}.bin"
        )
    #add_dependencies(app ${CMAKE_PROJECT_NAME}_firmware_bin)
endfunction()

function(esptool_package_storage new_name)
    add_custom_target(${CMAKE_PROJECT_NAME}_storage_bin ALL
        DEPENDS app #gen_project_binary
        COMMAND "${CMAKE_COMMAND}" -E copy "storage.bin" "${new_name}.bin"
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Package storage binary image to: ${new_name}.bin"
        )
    #add_dependencies(app ${CMAKE_PROJECT_NAME}_storage_bin)
endfunction()