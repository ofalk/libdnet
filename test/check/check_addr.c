
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <dnet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <check.h>

#define ADDR_FILL(a, ip)		\
	(a)->addr_type = ADDR_TYPE_IP;	\
	(a)->addr_bits = IP_ADDR_BITS;	\
	(a)->addr_ip = (ip)

#define SIN_FILL(s, ip, port)				\
	(s)->sin_len = sizeof(struct sockaddr_in);	\
	(s)->sin_family = AF_INET;			\
	(s)->sin_port = htons(port);			\
	(s)->sin_addr.s_addr = (ip)

typedef struct sockaddr SA;

START_TEST(test_addr_fill)
{
	struct addr a, b;

	memset(&a, 0, sizeof(a)); memset(&b, 0, sizeof(b));

	ADDR_FILL(&a, 666);
	addr_fill(&b, ADDR_TYPE_IP, IP_ADDR_BITS, &a.addr_ip, IP_ADDR_LEN);
	fail_unless(memcmp(&a, &b, sizeof(a)) == 0, "got different address");
}
END_TEST
	
START_TEST(test_addr_cmp)
{
	struct addr a, b;

	ADDR_FILL(&a, 666);
	memcpy(&b, &a, sizeof(a));
	fail_unless(addr_cmp(&a, &b) == 0, "failed on equal addresses");
	b.addr_type = ADDR_TYPE_ETH;
	fail_unless(addr_cmp(&a, &b) < 0, "failed on different addr_type");
	memcpy(&b, &a, sizeof(a)); b.addr_bits--;
	fail_unless(addr_cmp(&a, &b) < 0, "failed on different addr_bits");
	memcpy(&b, &a, sizeof(a)); b.addr_ip--;
	fail_unless(addr_cmp(&a, &b) < 0, "failed on different addr_ip");
}
END_TEST

START_TEST(test_addr_bcast)
{
	struct addr a, b;

	ADDR_FILL(&a, htonl(0x01020304));
	a.addr_bits = 29; addr_bcast(&a, &b);
	fail_unless(b.addr_ip == htonl(0x01020307), "wrong for /29");
	a.addr_bits = 16; addr_bcast(&a, &b);
	fail_unless(b.addr_ip == htonl(0x0102ffff), "wrong for /16");
	a.addr_bits = 5; addr_bcast(&a, &b);
	fail_unless(b.addr_ip == htonl(0x7ffffff), "wrong for /5");
}
END_TEST

START_TEST(test_addr_ntop)
{
	struct addr a;
	char buf[64];
	
	ADDR_FILL(&a, htonl(0x010203ff));
	a.addr_bits = 23; addr_ntop(&a, buf, sizeof(buf));
	fail_unless(strcmp(buf, "1.2.3.255/23") == 0, "bad /23 handling");
	a.addr_bits = 0; addr_ntop(&a, buf, sizeof(buf));
	fail_unless(strcmp(buf, "1.2.3.255/0") == 0, "bad /0 handling");
	a.addr_bits = 32; addr_ntop(&a, buf, sizeof(buf));
	fail_unless(strcmp(buf, "1.2.3.255") == 0, "bad /32 handling");
	fail_unless(addr_ntop(&a, buf, 9) < 0, "buffer overflow?");
}
END_TEST

START_TEST(test_addr_pton)
{
	struct addr a, b;

	ADDR_FILL(&a, htonl(0x010203ff));
	
	a.addr_bits = 17; addr_pton("1.2.3.255/17", &b);
	fail_unless(addr_cmp(&a, &b) == 0, "bad /17 handling");
	a.addr_bits = 32; addr_pton("1.2.3.255", &b);
	fail_unless(addr_cmp(&a, &b) == 0, "bad handling of missing /32");
	fail_unless(addr_pton("1.2.3.4/33", &b) < 0, "accepted /33");
	fail_unless(addr_pton("1.2.3.256", &b) < 0, "accepted .256");
	fail_unless(addr_pton("1.2.3.4.5", &b) < 0, "accepted quint octet");
	fail_unless(addr_pton("1.2.3", &b) < 0, "accepted quint octet");
	fail_unless(addr_pton("1.2.3", &b) < 0, "accepted triple octet");
	fail_unless(addr_pton("localhost", &b) == 0, "barfed on localhost");
	fail_unless(addr_pton("localhost/24", &b) == 0,
	    "barfed on localhost/24");
}
END_TEST

START_TEST(test_addr_ntoa)
{
	struct addr a;
	int i;

	ADDR_FILL(&a, htonl(0x01020304));
	for (i = 0; i < 1000; i++) {
		fail_unless(strcmp(addr_ntoa(&a), "1.2.3.4") == 0,
		    "barfed on 1.2.3.4 loop");
	}
}
END_TEST

START_TEST(test_addr_ntos)
{
	struct sockaddr_in s1, s2;
	struct addr a;

	memset(&s1, 0, sizeof(s1));
	memset(&s2, 0, sizeof(s2));
	SIN_FILL(&s1, htonl(0x01020304), 0);
	ADDR_FILL(&a, htonl(0x01020304));
	addr_ntos(&a, (SA *)&s2);
	fail_unless(memcmp(&s1, &s2, sizeof(s1)) == 0, "bad sockaddr_in");
}
END_TEST

START_TEST(test_addr_ston)
{
	struct sockaddr_in s, t;
	struct addr a, b;

	memset(&a, 0, sizeof(a));
	ADDR_FILL(&a, htonl(0x01020304));
	memcpy(&b, &a, sizeof(&b));
	SIN_FILL(&s, htonl(0x01020304), 0);
	memcpy(&t, &s, sizeof(&t));
	
	addr_ston((SA *)&s, &b);
	fail_unless(memcmp(&a, &b, sizeof(a)) == 0, "bad addr");
	s.sin_len = 0;
	fail_unless(addr_ston((SA *)&s, &b) == 0, "sin_len == 0");
	s.sin_family = 123;
	fail_unless(addr_ston((SA *)&s, &b) < 0, "sin_family == 123");
}
END_TEST

START_TEST(test_addr_btos)
{
}
END_TEST

START_TEST(test_addr_stob)
{
}
END_TEST

START_TEST(test_addr_btom)
{
}
END_TEST

START_TEST(test_addr_mtob)
{
}
END_TEST

Suite *
addr_suite(void)
{
	Suite *s = suite_create("addr");
	TCase *tc_core = tcase_create("core");

	suite_add_tcase(s, tc_core);
	tcase_add_test(tc_core, test_addr_fill);
	tcase_add_test(tc_core, test_addr_cmp);
	tcase_add_test(tc_core, test_addr_bcast);
	tcase_add_test(tc_core, test_addr_ntop);
	tcase_add_test(tc_core, test_addr_pton);
	tcase_add_test(tc_core, test_addr_ntoa);
	tcase_add_test(tc_core, test_addr_ntos);
	tcase_add_test(tc_core, test_addr_ston);
	tcase_add_test(tc_core, test_addr_btos);
	tcase_add_test(tc_core, test_addr_stob);
	tcase_add_test(tc_core, test_addr_btom);
	tcase_add_test(tc_core, test_addr_mtob);
	
	return (s);
}

int
main(void)
{
	Suite *s = addr_suite();
	SRunner *sr = srunner_create(s);
	int nf;
	
	srunner_run_all (sr, CK_NORMAL);
	nf = srunner_ntests_failed(sr);
	srunner_free(sr);
	suite_free(s);
	
	return (nf == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
