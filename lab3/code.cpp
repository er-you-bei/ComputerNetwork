#define _CRT_SECURE_NO_WARNINGS
#include <pcap.h>
#include <stdio.h>
#include <time.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")

// 以太网帧头部（14字节）
#pragma pack(push, 1)
struct ethernet_header {
    u_char dest_mac[6];
    u_char src_mac[6];
    u_short ether_type;
};

// IP头部
struct ip_header {
    u_char  ip_verlen;
    u_char  ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    u_char  ip_ttl;
    u_char  ip_p;
    u_short ip_sum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};

// 统计数据结构
struct traffic_stat {
    u_char src_mac[6];
    u_char dst_mac[6];
    struct in_addr src_ip;
    struct in_addr dst_ip;
    unsigned long total_bytes;
    int count;
};

#define MAX_STATS 1000
struct traffic_stat stats[MAX_STATS];
int stat_count = 0;
time_t last_report = 0;

// 获取当前时间字符串
void get_time_str(char* buffer, int size) {
    time_t now;
    struct tm* tm_info;
    time(&now);
    tm_info = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

// 更新统计信息
void update_stat(const u_char* src_mac, struct in_addr src_ip,
    const u_char* dst_mac, struct in_addr dst_ip,
    int len) {
    int found = 0;
    for (int i = 0; i < stat_count; i++) {
        if (memcmp(stats[i].src_mac, src_mac, 6) == 0 &&
            stats[i].src_ip.s_addr == src_ip.s_addr &&
            memcmp(stats[i].dst_mac, dst_mac, 6) == 0 &&
            stats[i].dst_ip.s_addr == dst_ip.s_addr) {
            stats[i].total_bytes += len;
            stats[i].count++;
            found = 1;
            break;
        }
    }
    if (!found && stat_count < MAX_STATS) {
        memcpy(stats[stat_count].src_mac, src_mac, 6);
        stats[stat_count].src_ip = src_ip;
        memcpy(stats[stat_count].dst_mac, dst_mac, 6);
        stats[stat_count].dst_ip = dst_ip;
        stats[stat_count].total_bytes = len;
        stats[stat_count].count = 1;
        stat_count++;
    }
}

// 打印统计信息
void print_stats() {
    printf("\n=== Traffic Statistics (last minute) ===\n");
    for (int i = 0; i < stat_count; i++) {
        printf("TX: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
            stats[i].src_mac[0], stats[i].src_mac[1], stats[i].src_mac[2],
            stats[i].src_mac[3], stats[i].src_mac[4], stats[i].src_mac[5],
            stats[i].dst_mac[0], stats[i].dst_mac[1], stats[i].dst_mac[2],
            stats[i].dst_mac[3], stats[i].dst_mac[4], stats[i].dst_mac[5]);
        printf("  %s -> %s, bytes: %lu, packets: %d\n",
            inet_ntoa(stats[i].src_ip), inet_ntoa(stats[i].dst_ip),
            stats[i].total_bytes, stats[i].count);
    }
    printf("========================================\n");
    stat_count = 0;
    memset(stats, 0, sizeof(stats));
}

// 数据包处理回调函数
void packet_handler(u_char* user, const struct pcap_pkthdr* header,
    const u_char* packet) {
    struct ethernet_header* eth = (struct ethernet_header*)packet;
    char time_buf[64];
    get_time_str(time_buf, sizeof(time_buf));

    // 检查是否IP包（EtherType = 0x0800）
    if (ntohs(eth->ether_type) == 0x0800) {
        struct ip_header* ip = (struct ip_header*)(packet + 14);
        int ip_header_len = (ip->ip_verlen & 0x0F) * 4;

        // CSV格式输出
        printf("%s,%02x:%02x:%02x:%02x:%02x:%02x,%s,%02x:%02x:%02x:%02x:%02x:%02x,%s,%d\n",
            time_buf,
            eth->src_mac[0], eth->src_mac[1], eth->src_mac[2],
            eth->src_mac[3], eth->src_mac[4], eth->src_mac[5],
            inet_ntoa(ip->ip_src),
            eth->dest_mac[0], eth->dest_mac[1], eth->dest_mac[2],
            eth->dest_mac[3], eth->dest_mac[4], eth->dest_mac[5],
            inet_ntoa(ip->ip_dst),
            header->len);

        // 更新统计信息
        update_stat(eth->src_mac, ip->ip_src, eth->dest_mac, ip->ip_dst, header->len);
    }

    // 每分钟输出一次统计
    time_t now = time(NULL);
    if (now - last_report >= 60) {
        print_stats();
        last_report = now;
    }
}

int main() {
    pcap_if_t* alldevs;
    pcap_if_t* d;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int inum;
    int i = 0;

    // 获取设备列表
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    // 打印设备列表
    printf("Available network interfaces:\n");
    for (d = alldevs; d != NULL; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description)\n");
    }

    if (i == 0) {
        printf("No interfaces found!\n");
        return 1;
    }

    printf("Enter the interface number (1-%d): ", i);
    scanf("%d", &inum);

    if (inum < 1 || inum > i) {
        printf("Invalid number!\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    // 跳转到选中的设备
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    // 打开设备进行捕获
    if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL) {
        fprintf(stderr, "Unable to open adapter: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    printf("\nListening on %s...\n", d->description);
    printf("Press Ctrl+C to stop.\n\n");
    printf("Time,Source MAC,Source IP,Destination MAC,Destination IP,Frame Length\n");

    pcap_freealldevs(alldevs);
    last_report = time(NULL);

    // 开始捕获
    pcap_loop(adhandle, 0, packet_handler, NULL);

    pcap_close(adhandle);
    return 0;
}