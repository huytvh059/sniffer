#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SNAPLEN 65535
#define TIMEOUT_MS 1000
#define BYTES_PER_ROW 16

static pcap_t *g_handle;
static volatile sig_atomic_t g_stop;

static void on_sigint(int signo)
{
    (void)signo;
    g_stop = 1;

    if (g_handle != NULL) {
        pcap_breakloop(g_handle);
    }
}

static void print_mac(const uint8_t *mac)
{
    printf(
        "%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
}

static void print_payload(const u_char *payload, size_t length)
{
    printf("  Payload: %zu byte(s)", length);

    if (length == 0U) {
        putchar('\n');
        return;
    }

    printf("\n");

    for (size_t i = 0; i < length; ++i) {
        /* In offset đầu mỗi dòng. */
        if (i % BYTES_PER_ROW == 0) {
            printf("    %04zx: ", i);
        }

        printf("%02x ", payload[i]);

        /* Xuống dòng sau mỗi BYTES_PER_ROW bytes. */
        if ((i + 1) % BYTES_PER_ROW == 0) {
            putchar('\n');
        }
    }

    /* Xuống dòng nếu dòng cuối chưa đầy BYTES_PER_ROW bytes. */
    if (length % BYTES_PER_ROW != 0) {
        putchar('\n');
    }
}

static int parse_ethernet(
    const struct pcap_pkthdr *header,
    const u_char *packet,
    size_t *offset
)
{
    if (header->caplen < sizeof(struct ether_header)) {
        fprintf(stderr, "  Truncated Ethernet header\n");
        return -1;
    }

    const struct ether_header *ethernet =
        (const struct ether_header *)packet;

    printf("  Ethernet: ");
    print_mac(ethernet->ether_shost);
    printf(" -> ");
    print_mac(ethernet->ether_dhost);
    printf(", type=0x%04x\n", ntohs(ethernet->ether_type));

    if (ntohs(ethernet->ether_type) != ETHERTYPE_IP) {
        printf("  Skipped: non-IPv4 frame\n");
        return -1;
    }

    /* Move past the Layer 2 Ethernet header. */
    *offset += sizeof(*ethernet);
    return 0;
}

static int parse_ipv4(
    const struct pcap_pkthdr *header,
    const u_char *packet,
    size_t *offset,
    uint8_t *protocol
)
{
    if ((size_t)header->caplen - *offset < sizeof(struct ip)) {
        fprintf(stderr, "  Truncated IPv4 header\n");
        return -1;
    }

    const struct ip *ipv4 = (const struct ip *)(packet + *offset);
    size_t ipv4_header_length = (size_t)ipv4->ip_hl * 4U;

    if (
        ipv4->ip_v != 4 ||
        ipv4_header_length < sizeof(*ipv4) ||
        (size_t)header->caplen - *offset < ipv4_header_length
    ) {
        fprintf(stderr, "  Invalid or truncated IPv4 header\n");
        return -1;
    }

    char source[INET_ADDRSTRLEN];
    char destination[INET_ADDRSTRLEN];

    if (
        inet_ntop(AF_INET, &ipv4->ip_src, source, sizeof(source)) == NULL ||
        inet_ntop(
            AF_INET,
            &ipv4->ip_dst,
            destination,
            sizeof(destination)
        ) == NULL
    ) {
        fprintf(stderr, "  inet_ntop failed: %s\n", strerror(errno));
        return -1;
    }

    printf(
        "  IPv4: %s -> %s, protocol=%u\n",
        source,
        destination,
        (unsigned int)ipv4->ip_p
    );

    *protocol = ipv4->ip_p;

    /* Move past the variable-length Layer 3 IPv4 header. */
    *offset += ipv4_header_length;

    if ((ntohs(ipv4->ip_off) & IP_OFFMASK) != 0) {
        printf("  Skipped: non-initial IPv4 fragment\n");
        return -1;
    }

    return 0;
}

static int parse_tcp(
    const struct pcap_pkthdr *header,
    const u_char *packet,
    size_t *offset
)
{
    if ((size_t)header->caplen - *offset < sizeof(struct tcphdr)) {
        fprintf(stderr, "  Truncated TCP header\n");
        return -1;
    }

    const struct tcphdr *tcp =
        (const struct tcphdr *)(packet + *offset);
    size_t tcp_header_length = (size_t)tcp->th_off * 4U;

    if (
        tcp_header_length < sizeof(*tcp) ||
        (size_t)header->caplen - *offset < tcp_header_length
    ) {
        fprintf(stderr, "  Invalid or truncated TCP header\n");
        return -1;
    }

    printf(
        "  TCP: %u -> %u\n",
        (unsigned int)ntohs(tcp->th_sport),
        (unsigned int)ntohs(tcp->th_dport)
    );

    /* Move past the variable-length Layer 4 TCP header. */
    *offset += tcp_header_length;
    return 0;
}

static int parse_udp(
    const struct pcap_pkthdr *header,
    const u_char *packet,
    size_t *offset
)
{
    if ((size_t)header->caplen - *offset < sizeof(struct udphdr)) {
        fprintf(stderr, "  Truncated UDP header\n");
        return -1;
    }

    const struct udphdr *udp =
        (const struct udphdr *)(packet + *offset);

    printf(
        "  UDP: %u -> %u\n",
        (unsigned int)ntohs(udp->uh_sport),
        (unsigned int)ntohs(udp->uh_dport)
    );

    /* Move past the fixed-length Layer 4 UDP header. */
    *offset += sizeof(*udp);
    return 0;
}

/* Callback pcap_loop; protocol-specific validation lives in parser functions. */
static void packet_handler(
    u_char *user,
    const struct pcap_pkthdr *header,
    const u_char *packet
)
{
    (void)user;
    static unsigned long packet_number;
    size_t offset = 0;
    uint8_t protocol = 0;

    ++packet_number;
    printf(
        "\nPacket #%lu: captured=%u, wire=%u\n",
        packet_number,
        header->caplen,
        header->len
    );

    if (parse_ethernet(header, packet, &offset) != 0) {
        return;
    }

    if (parse_ipv4(header, packet, &offset, &protocol) != 0) {
        return;
    }

    if (protocol == IPPROTO_TCP) {
        if (parse_tcp(header, packet, &offset) != 0) {
            return;
        }
    } else if (protocol == IPPROTO_UDP) {
        if (parse_udp(header, packet, &offset) != 0) {
            return;
        }
    } else {
        printf("  Skipped: neither TCP nor UDP\n");
        return;
    }

    print_payload(
        packet + offset,
        (size_t)header->caplen - offset
    );
}

static int set_option(pcap_t *pcap, int result, const char *name)
{
    if (result != 0) {
        fprintf(stderr, "%s failed: %s\n", name, pcap_geterr(pcap));
        return -1;
    }

    return 0;
}

/*
 * Liệt kê tất cả card mạng, hiển thị thông tin chi tiết và cho phép
 * người dùng chọn tương tác. Trả về tên interface được chọn.
 * Caller chịu trách nhiệm giải phóng danh sách bằng pcap_freealldevs().
 */
static const char *select_interface(pcap_if_t **out_alldevs)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t *alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_findalldevs failed: %s\n", errbuf);
        return NULL;
    }

    if (alldevs == NULL) {
        fprintf(stderr, "No network interfaces found.\n"
                        "Make sure you have root privileges.\n");
        return NULL;
    }

    printf("\n========================================\n");
    printf("  Available Network Interfaces\n");
    printf("========================================\n");

    int count = 0;
    for (pcap_if_t *dev = alldevs; dev != NULL; dev = dev->next) {
        ++count;
        printf("\n  [%d] %s\n", count, dev->name);

        /* Hiển thị mô tả nếu có. */
        if (dev->description != NULL) {
            printf("      Description : %s\n", dev->description);
        }

        /* Hiển thị trạng thái loopback/up/running. */
        printf("      Flags       :");
        if (dev->flags & PCAP_IF_LOOPBACK) {
            printf(" LOOPBACK");
        }
        if (dev->flags & PCAP_IF_UP) {
            printf(" UP");
        }
        if (dev->flags & PCAP_IF_RUNNING) {
            printf(" RUNNING");
        }
        putchar('\n');

        /* Hiển thị địa chỉ IP gắn với interface. */
        for (pcap_addr_t *addr = dev->addresses; addr != NULL; addr = addr->next) {
            if (addr->addr == NULL) {
                continue;
            }

            if (addr->addr->sa_family == AF_INET) {
                char ip[INET_ADDRSTRLEN];
                struct sockaddr_in *sin =
                    (struct sockaddr_in *)addr->addr;

                if (inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip)) != NULL) {
                    printf("      IPv4        : %s\n", ip);
                }
            } else if (addr->addr->sa_family == AF_INET6) {
                char ip6[INET6_ADDRSTRLEN];
                struct sockaddr_in6 *sin6 =
                    (struct sockaddr_in6 *)addr->addr;

                if (inet_ntop(AF_INET6, &sin6->sin6_addr, ip6, sizeof(ip6)) != NULL) {
                    printf("      IPv6        : %s\n", ip6);
                }
            }
        }
    }

    printf("\n========================================\n");
    printf("Select interface [1-%d]: ", count);
    fflush(stdout);

    int choice = 0;
    if (scanf("%d", &choice) != 1 || choice < 1 || choice > count) {
        fprintf(stderr, "Invalid selection.\n");
        pcap_freealldevs(alldevs);
        return NULL;
    }

    /* Dịch chuyển tới interface được chọn. */
    pcap_if_t *selected = alldevs;
    for (int i = 1; i < choice; ++i) {
        selected = selected->next;
    }

    printf("\n  => Capturing on: %s\n\n", selected->name);
    *out_alldevs = alldevs;
    return selected->name;
}

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t *alldevs = NULL;
    const char *ifname = NULL;

    if (argc >= 2) {
        /* Truyền tên interface trực tiếp qua dòng lệnh (tương thích ngược). */
        ifname = argv[1];
    } else {
        /* Không có tham số: hiển thị menu chọn card mạng tương tác. */
        ifname = select_interface(&alldevs);

        if (ifname == NULL) {
            return EXIT_FAILURE;
        }
    }

    pcap_t *pcap = pcap_create(ifname, errbuf);

    if (pcap == NULL) {
        fprintf(stderr, "pcap_create(%s) failed: %s\n", ifname, errbuf);

        if (alldevs != NULL) {
            pcap_freealldevs(alldevs);
        }

        return EXIT_FAILURE;
    }

    if (
        set_option(
            pcap,
            pcap_set_snaplen(pcap, SNAPLEN),
            "pcap_set_snaplen"
        ) != 0 ||
        set_option(
            pcap,
            pcap_set_promisc(pcap, 1),
            "pcap_set_promisc"
        ) != 0 ||
        set_option(
            pcap,
            pcap_set_timeout(pcap, TIMEOUT_MS),
            "pcap_set_timeout"
        ) != 0 ||
        set_option(
            pcap,
            pcap_set_immediate_mode(pcap, 1),
            "pcap_set_immediate_mode"
        ) != 0
    ) {
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    int activation_status = pcap_activate(pcap);

    if (activation_status < 0) {
        fprintf(
            stderr,
            "pcap_activate failed: %s\n",
            pcap_statustostr(activation_status)
        );
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    if (activation_status > 0) {
        fprintf(
            stderr,
            "pcap_activate warning: %s\n",
            pcap_statustostr(activation_status)
        );
    }

    int link_type = pcap_datalink(pcap);
    const char *link_name = pcap_datalink_val_to_name(link_type);

    if (link_type != DLT_EN10MB) {
        fprintf(
            stderr,
            "Unsupported data-link type: %s (Ethernet required)\n",
            link_name != NULL ? link_name : "unknown"
        );
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = on_sigint;

    if (
        sigemptyset(&action.sa_mask) == -1 ||
        sigaction(SIGINT, &action, NULL) == -1
    ) {
        fprintf(stderr, "Signal setup failed: %s\n", strerror(errno));
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    /* alldevs không còn cần thiết sau khi pcap đã được tạo. */
    if (alldevs != NULL) {
        pcap_freealldevs(alldevs);
        alldevs = NULL;
    }

    g_handle = pcap;
    printf("Capturing on %s. Press Ctrl+C to stop.\n", ifname);

    int loop_result = pcap_loop(pcap, -1, packet_handler, NULL);
    g_handle = NULL;

    if (loop_result == PCAP_ERROR && !g_stop) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(pcap));
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    struct pcap_stat stats;

    if (pcap_stats(pcap, &stats) == -1) {
        fprintf(stderr, "pcap_stats failed: %s\n", pcap_geterr(pcap));
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    printf(
        "\nCapture statistics:\n"
        "  Received: %u\n"
        "  Kernel dropped: %u\n"
        "  Interface dropped: %u\n",
        stats.ps_recv,
        stats.ps_drop,
        stats.ps_ifdrop
    );

    pcap_close(pcap);
    return EXIT_SUCCESS;
}
