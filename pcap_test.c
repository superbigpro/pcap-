#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>

   // 패킷 정보를 출력하는 함수
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    const struct ether_header *eth_header = (struct ether_header *)packet; // 이더넷 헤더로 패킷을 캐스팅
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) { // IP 패킷이 아니면 함수 종료
        fprintf(stderr, "Not an IP packet.\n\n");
        return;
    }

    // IP 헤더 정보 추출
    const struct ip *ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    int ip_header_length = (ip_header->ip_hl) * 4; // IP 헤더 길이 계산
    // TCP 헤더 정보 추출
    const struct tcphdr *tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip_header_length);
    int tcp_header_length = (tcp_header->th_off) * 4; // TCP 헤더 길이 계산
        
    // 페이로드 길이 계산
    int payload_length = ntohs(ip_header->ip_len) - (ip_header_length + tcp_header_length);
    const u_char *payload = packet + sizeof(struct ether_header) + ip_header_length + tcp_header_length; // 페이로드 위치 설정
        
    // 소스 및 목적지 MAC, IP, 포트 및 페이로드 정보 출력
    printf("Src MAC: %s\n", ether_ntoa((struct ether_addr *)&eth_header->ether_shost));
    printf("Dst MAC: %s\n", ether_ntoa((struct ether_addr *)&eth_header->ether_dhost));
    printf("Src IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Dst IP: %s\n", inet_ntoa(ip_header->ip_dst));
    printf("Src Port: %d\n", ntohs(tcp_header->th_sport));
    printf("Dst Port: %d\n", ntohs(tcp_header->th_dport));
    printf("Payload (%d bytes): ", payload_length);
    for (int i = 0; i < payload_length; i++) {
        printf("%02x ", payload[i]); // 페이로드의 각 바이트를 16진수로 출력
    }
    printf("\n\n");
}

int main() {
    pcap_t *handle; // 패킷 캡처 핸들
    char error_buffer[PCAP_ERRBUF_SIZE]; // 에러 메시지 버퍼
    pcap_if_t *alldevs; // 모든 네트워크 디바이스 목록
    const u_char *packet; // 캡처된 패킷 포인터
    struct pcap_pkthdr packet_header; // 캡처된 패킷 헤더

    // 네트워크 디바이스 찾기
    if (pcap_findalldevs(&alldevs, error_buffer) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", error_buffer);
        return 2; // 디바이스 찾기 실패 시 프로그램 종료
    }

    // 첫 번째 네트워크 디바이스 선택
    if (alldevs == NULL) {
        fprintf(stderr, "No devices found.\n");
        return 2; // 디바이스 없음 시 프로그램 종료
    }
    printf("Using device %s\n", alldevs->name); // 선택된 디바이스 출력

    // 디바이스 오픈
    handle = pcap_open_live(alldevs->name, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", alldevs->name, error_buffer);
        pcap_freealldevs(alldevs); // 디바이스 목록 해제
        return 2; // 디바이스 오픈 실패 시 프로그램 종료
    }

    // 패킷 캡처 및 처리 루프
    while ((packet = pcap_next(handle, &packet_header)) != NULL) {
        print_packet_info(packet, packet_header); // 패킷 정보 출력 함수 호출
    }

    pcap_close(handle); // 핸들 닫기
    pcap_freealldevs(alldevs); // 디바이스 목록 해제

    return 0;
}
