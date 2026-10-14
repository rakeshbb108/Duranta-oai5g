# SPDX-License-Identifier: LicenseRef-CSSL-1.0

add_executable(xnap_lib_test xnap_lib_test.c)
add_dependencies(tests xnap_lib_test)
add_test(NAME xnap_lib_test COMMAND xnap_lib_test)
target_link_libraries(xnap_lib_test PRIVATE xnap_lib ds LOG)
target_link_libraries(xnap_lib_test PRIVATE asn1_xnap)
target_include_directories(xnap_lib_test PRIVATE 
			   ${CMAKE_SOURCE_DIR}
                           ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(xnap_ids_test xnap_ids_test.c ${OPENAIR2_DIR}/XNAP/xnap_ids.c)
add_dependencies(tests xnap_ids_test)
add_test(NAME xnap_ids_test COMMAND xnap_ids_test)
target_link_libraries(xnap_ids_test PRIVATE ds minimal_lib)
target_include_directories(xnap_ids_test PRIVATE ${CMAKE_SOURCE_DIR})
