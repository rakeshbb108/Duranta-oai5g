# SPDX-License-Identifier: LicenseRef-CSSL-1.0

add_executable(snow3g_tests snow3g_tests.c)
target_link_libraries(snow3g_tests PRIVATE nr_pdcp_snow3g minimal_lib SECURITY)
add_test(NAME snow3g_tests
         COMMAND snow3g_tests)
add_dependencies(tests snow3g_tests)

add_executable(pdcp_count_tests
               pdcp_count_tests.c
               ../nr_pdcp_entity.c
               ../nr_pdcp_sdu.c
               ../nr_pdcp_security_nea2.c
               ../nr_pdcp_integrity_nia2.c)
target_link_libraries(pdcp_count_tests PRIVATE nr_pdcp_snow3g minimal_lib SECURITY)
add_test(NAME pdcp_count_tests
         COMMAND pdcp_count_tests)
add_dependencies(tests pdcp_count_tests)

add_executable(pdcp_forwarding_tests
               pdcp_forwarding_tests.c
               ../nr_pdcp_entity.c
               ../nr_pdcp_sdu.c
               ../nr_pdcp_security_nea2.c
               ../nr_pdcp_integrity_nia2.c)
target_link_libraries(pdcp_forwarding_tests PRIVATE nr_pdcp_snow3g minimal_lib SECURITY)
add_test(NAME pdcp_forwarding_tests
         COMMAND pdcp_forwarding_tests)
add_dependencies(tests pdcp_forwarding_tests)
