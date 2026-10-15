# SPDX-License-Identifier: LicenseRef-CSSL-1.0

add_executable(f1u_dl_delivery_test f1u_dl_delivery_test.c ../f1u_dl_delivery.c)
target_link_libraries(f1u_dl_delivery_test PRIVATE LOG minimal_lib)
add_test(NAME f1u_dl_delivery_test COMMAND f1u_dl_delivery_test)
add_dependencies(tests f1u_dl_delivery_test)
