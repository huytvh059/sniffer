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
#define HEX_BYTES 16

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
    size_t shown = length < HEX_BYTES ? length : HEX_BYTES;

    printf("  Payload: %zu byte(s)", length);

    if (shown > 0U) {
        printf("; first %zu byte(s):", shown);

        for (size_t i = 0; i < shown; ++i) {
            printf(" %02x", payload[i]);
        }
    }

    putchar('\n');
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

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    if (argc != 2) {
        fprintf(
            stderr,
            "Usage: %s <network-interface>\nExample: %s eth0\n",
            argv[0],
            argv[0]
        );
        return EXIT_FAILURE;
    }

    pcap_t *pcap = pcap_create(argv[1], errbuf);

    if (pcap == NULL) {
        fprintf(
            stderr,
            "pcap_create(%s) failed: %s\n",
            argv[1],
            errbuf
        );
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

    g_handle = pcap;
    printf("Capturing on %s. Press Ctrl+C to stop.\n", argv[1]);

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
