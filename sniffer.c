#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <signal.h>
#include <arpa/inet.h>
#include <ctype.h>

#define OUTPUT_FILE "packets.list"
#define PCAP_DUMP_FILE "packets.pcap"
#define MAX_PACKET_LEN 65536

FILE *output = NULL;
pcap_dumper_t *pcap_dumper = NULL;
pcap_t *handle = NULL;

volatile sig_atomic_t stop_capture = 0;
int packet_count = 0;

void handle_sigint(int sig) {
    stop_capture = 1;
    pcap_breakloop(handle);
}

void write_hex(const u_char *data, int len) {
    for (int i = 0; i < len; i++) {
        fprintf(output, "%02X ", data[i]);
        if ((i + 1) % 16 == 0) fprintf(output, "\n");
    }
    if (len % 16 != 0) fprintf(output, "\n");
}

void write_ascii(const u_char *data, int len) {
    fprintf(output, "ASCII: ");
    for (int i = 0; i < len; i++) {
        if (isprint(data[i])) fprintf(output, "%c", data[i]);
        else fprintf(output, ".");
    }
    fprintf(output, "\n");
}

void print_ip_info(const struct ip *iph) {
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->ip_src, src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &iph->ip_dst, dst, INET_ADDRSTRLEN);
    fprintf(output, "IP src: %s -> dst: %s\n", src, dst);
    fprintf(output, "Protocol: %d\n", iph->ip_p);
}

void print_tcp_info(const struct tcphdr *tcph, const u_char *payload, int payload_len) {
    fprintf(output, "TCP src port: %d -> dst port: %d\n", ntohs(tcph->source), ntohs(tcph->dest));
    if (payload_len > 0) {
        if (strncmp((char *)payload, "GET", 3) == 0 || strncmp((char *)payload, "POST", 4) == 0 || strstr((char *)payload, "HTTP")) {
            fprintf(output, "HTTP Data:\n%.*s\n", payload_len, payload);
        }
    }
}

void print_udp_info(const struct udphdr *udph, const u_char *payload, int payload_len) {
    fprintf(output, "UDP src port: %d -> dst port: %d\n", ntohs(udph->source), ntohs(udph->dest));
    if (ntohs(udph->source) == 53 || ntohs(udph->dest) == 53) {
        fprintf(output, "DNS (brut):\n%.*s\n", payload_len, payload);
    }
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    packet_count++;

    time_t rawtime = h->ts.tv_sec;
    struct tm *timeinfo = localtime(&rawtime);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);

    fprintf(output, "=== Packet %d ===\n", packet_count);
    fprintf(output, "Time: %s.%06ld\n", timestamp, h->ts.tv_usec);
    fprintf(output, "Length: %d bytes\n", h->len);

    struct ether_header *eth = (struct ether_header *)bytes;
    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        struct ip *iph = (struct ip *)(bytes + sizeof(struct ether_header));
        int ip_len = iph->ip_hl * 4;
        print_ip_info(iph);

        if (iph->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr *)((u_char *)iph + ip_len);
            int tcp_len = tcph->doff * 4;
            const u_char *payload = (u_char *)tcph + tcp_len;
            int payload_len = ntohs(iph->ip_len) - ip_len - tcp_len;
            print_tcp_info(tcph, payload, payload_len);
        } else if (iph->ip_p == IPPROTO_UDP) {
            struct udphdr *udph = (struct udphdr *)((u_char *)iph + ip_len);
            const u_char *payload = (u_char *)udph + sizeof(struct udphdr);
            int payload_len = ntohs(udph->len) - sizeof(struct udphdr);
            print_udp_info(udph, payload, payload_len);
        }
    }

    fprintf(output, "Data (hex):\n");
    write_hex(bytes, h->len);
    write_ascii(bytes, h->len);
    fprintf(output, "\n");
    fflush(output);

    pcap_dump((u_char *)pcap_dumper, h, bytes); // Save to .pcap
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device;
    int i = 0, dev_index = 0;

    signal(SIGINT, handle_sigint);

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Erreur (findalldevs): %s\n", errbuf);
        return 1;
    }

    printf("Interfaces disponibles :\n");
    for (device = alldevs; device != NULL; device = device->next) {
        printf(" [%d] %s\n", i++, device->name);
    }

    if (i == 0) {
        fprintf(stderr, "Aucune interface trouvée\n");
        return 1;
    }

    printf("Choisir l'interface (numéro) : ");
    scanf("%d", &dev_index);

    for (i = 0, device = alldevs; device && i < dev_index; i++, device = device->next);

    if (!device) {
        fprintf(stderr, "Index invalide\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    printf("Interface sélectionnée : %s\n", device->name);

    handle = pcap_open_live(device->name, MAX_PACKET_LEN, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Erreur (open_live): %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    output = fopen(OUTPUT_FILE, "w");
    if (!output) {
        perror("Erreur ouverture fichier texte");
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 1;
    }

    pcap_dumper = pcap_dump_open(handle, PCAP_DUMP_FILE);
    if (!pcap_dumper) {
        fprintf(stderr, "Erreur ouverture fichier pcap : %s\n", pcap_geterr(handle));
        fclose(output);
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 1;
    }

    fprintf(output, "=== Capture démarrée sur %s ===\n", device->name);
    fflush(output);

    pcap_loop(handle, -1, packet_handler, NULL);

    fprintf(output, "\n=== Fin de capture ===\n");
    fprintf(output, "Nombre total de paquets : %d\n", packet_count);

    fclose(output);
    pcap_dump_close(pcap_dumper);
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}