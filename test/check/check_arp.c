
#include <sys/types.h>

#include <dnet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <check.h>

START_TEST(test_arp_fill)
{
}
END_TEST

START_TEST(test_arp_open)
{
}
END_TEST

START_TEST(test_arp_add)
{
}
END_TEST

START_TEST(test_arp_delete)
{
}
END_TEST

START_TEST(test_arp_get)
{
}
END_TEST

START_TEST(test_arp_loop)
{
}
END_TEST

START_TEST(test_arp_close)
{
}
END_TEST

Suite *
arp_suite(void)
{
	Suite *s = suite_create("arp");
	TCase *tc_core = tcase_create("core");

	suite_add_tcase(s, tc_core);
	tcase_add_test(tc_core, test_arp_fill);
	tcase_add_test(tc_core, test_arp_open);
	tcase_add_test(tc_core, test_arp_add);
	tcase_add_test(tc_core, test_arp_delete);
	tcase_add_test(tc_core, test_arp_get);
	tcase_add_test(tc_core, test_arp_loop);
	tcase_add_test(tc_core, test_arp_close);
	
	return (s);
}

int
main(void)
{
	Suite *s = arp_suite();
	SRunner *sr = srunner_create(s);
	int nf;
	
	srunner_run_all (sr, CK_NORMAL);
	nf = srunner_ntests_failed(sr);
	srunner_free(sr);
	suite_free(s);
	
	return (nf == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
