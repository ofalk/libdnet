
#include <sys/types.h>

#include <dnet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <check.h>

START_TEST(test_route_open)
{
}
END_TEST

START_TEST(test_route_add)
{
}
END_TEST

START_TEST(test_route_delete)
{
}
END_TEST

START_TEST(test_route_get)
{
}
END_TEST

START_TEST(test_route_loop)
{
}
END_TEST

START_TEST(test_route_close)
{
}
END_TEST

Suite *
route_suite(void)
{
	Suite *s = suite_create("route");
	TCase *tc_core = tcase_create("core");

	suite_add_tcase(s, tc_core);
	tcase_add_test(tc_core, test_route_open);
	tcase_add_test(tc_core, test_route_add);
	tcase_add_test(tc_core, test_route_delete);
	tcase_add_test(tc_core, test_route_get);
	tcase_add_test(tc_core, test_route_loop);
	tcase_add_test(tc_core, test_route_close);
	
	return (s);
}

int
main(void)
{
	Suite *s = route_suite();
	SRunner *sr = srunner_create(s);
	int nf;
	
	srunner_run_all (sr, CK_NORMAL);
	nf = srunner_ntests_failed(sr);
	srunner_free(sr);
	suite_free(s);
	
	return (nf == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
