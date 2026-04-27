#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <string.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

char *host;
int host_len;

static u_int32_t print_pkt (struct nfq_data *tb, int *blocked)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);

	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		printf("payload_len=%d\n", ret);

		u_int32_t ip_len = (data[0] & 0xf) * 4;
		u_int32_t tcp_len = ((data[ip_len + 12] >> 4) & 0xf) * 4;
		u_int32_t http_len = ret - ip_len - tcp_len;

		if (http_len > 0) {
			unsigned char *http = data + ip_len + tcp_len;

			if (strncmp((char *)http, "GET", 3) == 0 ||
			    strncmp((char *)http, "POST", 4) == 0 ||
			    strncmp((char *)http, "PUT", 3) == 0 ||
			    strncmp((char *)http, "DELETE", 6) == 0 ||
			    strncmp((char *)http, "PATCH", 5) == 0 ||
			    strncmp((char *)http, "HEAD", 4) == 0 ||
			    strncmp((char *)http, "OPTIONS", 7) == 0 ||
			    strncmp((char *)http, "CONNECT", 7) == 0)
			{
				char *host_ptr = strstr((char *)http, "Host: ");
				if (host_ptr) {
					host_ptr += 6;
					char *end = strpbrk(host_ptr, "\r\n");
					if (end && (end - host_ptr) == host_len &&
					    strncmp(host_ptr, host, host_len) == 0) {
						printf("\n It is malicious!\n");
						*blocked = 1;
					}
				}
			}
		}
	}

	fputc('\n', stdout);
	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	int blocked = 0;
	u_int32_t id = print_pkt(nfa, &blocked);
	printf("entering callback\n");

	if (blocked)
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	else
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	if (argc < 2) {
		fprintf(stderr, "syntax : netfilter-test <host>\n");
		fprintf(stderr, "sample : netfilter-test test.gilgil.net\n");
		exit(1);
	}

	host_len = strlen(argv[1]);
	host = (char*)malloc(host_len + 1);
	if (!host) {
		fprintf(stderr, "malloc failed\n");
		exit(1);
	}
	memcpy(host, argv[1], host_len + 1);

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h, 0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	free(host);

	exit(0);
}
