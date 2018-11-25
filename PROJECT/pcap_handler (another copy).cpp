#include <pcap.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <cstring>
#include <unordered_map>
#include <time.h>
#include <sys/times.h>
#include <vector>
#include <set>
// -lpcap flag
#define SCAN_DELAY 3
#define PORT_CHANGE 0xff
//should find a way to record host data to detect possible scans, mb use mapping or hashing structure to save hosts
struct host
{
  host* next; // if same ip_src, but different ip_dst;; for future implementations
  struct in_addr ip_src, ip_dst;
  clock_t time_update;
  time_t create_time;
  int port_count;
  int scan_weight;//ports from 0-1023 have higher weight
  unsigned short source_port;
  std::set<unsigned short> ports;
  unsigned char flags_or; //TCP flags from dest|| urg/ack/psh/rst/syn/fin || 00111111|| xmas = 00101001 || fin = 00000001 || null = 00000000
  //|| half-open = 00010110 or 000000010 || if rst/ack or syn/ack or just rst then outgoing packet
  unsigned char flags;
  unsigned int protocol;// UDP||ICMP||TCP
  clock_t scan_delay_avg;
  //unsigned char tos; //type of service, do i need that?
  ~host() { if(next != nullptr) delete next;}
};

//mb add filename to logfiles???
//FILE* icmp_logfile;
//FILE* tcp_logfile;
//FILE* udp_logfile;

int total_quant, tcp_quant, icmp_quant, udp_quant, other_quant;
int null_scans, xmas_scans, udp_scans, tcp_scans, icmp_requests, halfopen_scans;

std::unordered_map<unsigned int, host> hosts;//for easy access of the host

void packetHandler(u_char *args, const struct pcap_pkthdr *pkt_header, const u_char *packet)
{
  struct ether_header* ethernetHeader;
  ethernetHeader = (struct ether_header*) packet;
//  printf("Size of the packet: %d\n", pkt_header->len);
  if(ntohs(ethernetHeader->ether_type) != ETHERTYPE_IP)
  {
    //printf("Not an IPv4 packet. Skipping...\n\n");
    return;
  }
  ++total_quant;

  struct ip* ipHeader;
  ipHeader = (struct ip*)(packet + sizeof(*ethernetHeader));
  char sourceIP[INET_ADDRSTRLEN];
  char destIP[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);//AF_INET for IPv4 protocol
  inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);
  unsigned int sourcePort, destPort;

  unsigned char flags;
  struct tms buf;//???
  clock_t now;
  struct host current, last;
  int count, index;

  if(ipHeader->ip_p == IPPROTO_ICMP)//Loose source routing packets are skipped, they are used for determining network path for ip datagrams
  {

    ++icmp_quant;
    struct icmphdr* icmpHeader;
    icmpHeader = (struct icmphdr*)(packet + sizeof(*ethernetHeader) + sizeof(*ipHeader));//Libpcap doesn't consider options and padding fields in ipv4 header

    if(icmpHeader->type == ICMP_ECHO && strcmp(sourceIP, destIP) != 0)
    {
      ++icmp_requests;
      //icmp_logfile = fopen("ICMP_log.txt", "a");
      /*printf("**********************************************\n");
      printf("ICMP echo request packet detected from %s to %s\n", sourceIP, destIP);
      printf("**********************************************\n");
      */
    }
  }
  else if(ipHeader->ip_p == IPPROTO_UDP)
  {
    ++udp_quant;
    struct udphdr* udpHeader;
    udpHeader = (struct udphdr*)(packet + sizeof(*ethernetHeader) + sizeof(*ipHeader));
    now = times(&buf);

    auto it = hosts.find(ipHeader->ip_src.s_addr);
    //Filling in the host information
    if(it == hosts.end()){
      current.time_update = now;
      current.create_time = time(NULL);
      current.ip_src = ipHeader->ip_src;
      current.ip_dst = ipHeader->ip_dst;
      current.source_port = udpHeader->source;
      current.scan_weight = udpHeader->dest < 1024 ? 3 : 1;// well-known ports weght more
      current.ports.insert(udpHeader->dest);
      current.port_count = current.ports.size();
      current.flags = 0;
      current.protocol = IPPROTO_UDP;
      hosts[ipHeader->ip_src.s_addr] = current;
    }
    else
    {
      if(((it->second).ip_dst.s_addr != ipHeader->ip_dst.s_addr) or (it->second.source_port != udpHeader->source) or (it->second.protocol != IPPROTO_UDP))
      {
        if(it->second.next == nullptr){
          it->second.next = new host();
          it->second.next->time_update = now;
          it->second.next->create_time = time(NULL);
          it->second.next->ip_src = ipHeader->ip_src;
          it->second.next->ip_dst = ipHeader->ip_dst;
          it->second.next->source_port = udpHeader->source;
          it->second.next->scan_weight = udpHeader->dest < 1024 ? 3 : 1;// well-known ports weght more
          it->second.next->ports.insert(udpHeader->dest);
          it->second.next->port_count = it->second.next->ports.size();
          it->second.next->flags = 0;
          it->second.next->protocol = IPPROTO_UDP;
        }
        else{
          for(auto n_ptr = it->second.next; n_ptr != nullptr; n_ptr = n_ptr->next)
          {
            bool sameIPdest = n_ptr->ip_dst.s_addr == ipHeader->ip_dst.s_addr;
            bool samePort = n_ptr->source_port == udpHeader->source;
            bool sameProtocol = n_ptr->protocol == IPPROTO_UDP;
            if(sameIPdest && samePort && sameProtocol)
            {
              if((it->second.next->ports.insert(udpHeader->dest)).second == true)
              {
                n_ptr->port_count += 1;
                n_ptr->scan_weight += udpHeader->dest < 1024 ? 3 : 1;
                n_ptr->scan_delay_avg += now - n_ptr->time_update;
                n_ptr->time_update = now;
              }
            }
            else
            {
              n_ptr = new host();
              n_ptr->time_update = now;
              n_ptr->create_time = time(NULL);
              n_ptr->ip_src = ipHeader->ip_src;
              n_ptr->ip_dst = ipHeader->ip_dst;
              n_ptr->source_port = udpHeader->source;
              n_ptr->scan_weight = udpHeader->dest < 1024 ? 3 : 1;// well-known ports weght more
              n_ptr->ports.insert(udpHeader->dest);
              n_ptr->port_count = n_ptr->ports.size();
              n_ptr->flags = 0;
              n_ptr->protocol = IPPROTO_UDP;
            }
          }
        }
      }
    }
    //UDP nmap scans send empty data packets, based on their documentation and the sample file provided
    //unsigned char*)(packet + sizeof(*ethernetHeader) + sizeof(*ipHeader) + sizeof(*udpHeader)) payload

    //udp_logfile = fopen("UDP_log.txt", "a");

  }
  else if(ipHeader->ip_p == IPPROTO_TCP)
  {
    ++tcp_quant;
    const struct tcphdr* tcpHeader;
    tcpHeader = (struct tcphdr*)(packet + sizeof(*ethernetHeader) + sizeof(*ipHeader));
    //tcp_logfile = fopen("TCP_log.txt", "a");
    now = times(&buf);
    unsigned short s_port = tcpHeader->th_sport;
    auto it = hosts.find(ipHeader->ip_src.s_addr);
    //Filling in the host information
    if(it == hosts.end()){
      current.time_update = now;
      current.create_time = time(NULL);
      current.ip_src = ipHeader->ip_src;
      current.ip_dst = ipHeader->ip_dst;
      current.source_port = tcpHeader->th_sport;
      current.scan_weight = tcpHeader->th_dport < 1024 ? 3 : 1;// well-known ports weght more
      current.ports.insert(tcpHeader->th_dport);
      current.port_count = current.ports.size();
      current.flags = tcpHeader->th_flags;
      current.protocol = IPPROTO_TCP;
      // auto search_host = hosts.find(ipHeader->ip_dst.s_addr);
      // if(search_host != hosts.end())
      //   if(current.ip_src.s_addr == search_host->second.ip_dst.s_addr && current.ip_dst.s_addr == search_host->second.ip_src.s_addr)
      //     current.flags_or |= search_host->second.flags;

      hosts[ipHeader->ip_src.s_addr] = current;
    }
    else
    {
      if(((it->second).ip_dst.s_addr != ipHeader->ip_dst.s_addr) or (it->second.source_port != tcpHeader->th_sport) or (it->second.protocol != IPPROTO_TCP))
      {
        if(it->second.next == nullptr){
          it->second.next = new host();
          it->second.next->time_update = now;
          it->second.next->create_time = time(NULL);
          it->second.next->ip_src = ipHeader->ip_src;
          it->second.next->ip_dst = ipHeader->ip_dst;
          it->second.next->source_port = tcpHeader->th_sport;
          it->second.next->scan_weight = tcpHeader->th_dport < 1024 ? 3 : 1;// well-known ports weght more
          it->second.next->ports.insert(tcpHeader->th_dport);
          it->second.next->port_count = it->second.next->ports.size();
          it->second.next->flags = tcpHeader->th_flags;
          it->second.next->protocol = IPPROTO_TCP;
          //auto search_host = hosts.find(ipHeader->ip_dst.s_addr);
          // if(search_host != hosts.end())
          //   if(it->second.next->ip_src.s_addr == search_host->second.ip_dst.s_addr && it->second.next->ip_dst.s_addr == search_host->second.ip_src.s_addr)
          //     it->second.next->flags_or |= search_host->second.flags;
        }
        else {
          for(auto n_ptr = it->second.next; n_ptr != nullptr; n_ptr = n_ptr->next)
          {
            bool sameIPdest = n_ptr->ip_dst.s_addr == ipHeader->ip_dst.s_addr;
            bool samePort = n_ptr->source_port == tcpHeader->source;
            bool sameProtocol = n_ptr->protocol == IPPROTO_TCP;
            if(sameIPdest && samePort && sameProtocol)
            {
              if((n_ptr->ports.insert(tcpHeader->th_dport)).second == true)
              {
                n_ptr->port_count += 1;
                n_ptr->scan_weight += tcpHeader->th_dport < 1024 ? 3 : 1;
                n_ptr->scan_delay_avg += now - n_ptr->time_update;
                n_ptr->time_update = now;
                n_ptr->protocol = IPPROTO_TCP;
                if(n_ptr->source_port != s_port) n_ptr->flags |= PORT_CHANGE;
              }
            }
            else
            {
              n_ptr = new host();
              n_ptr->time_update = now;
              n_ptr->create_time = time(NULL);
              n_ptr->ip_src = ipHeader->ip_src;
              n_ptr->ip_dst = ipHeader->ip_dst;
              n_ptr->source_port = tcpHeader->th_sport;
              n_ptr->scan_weight = tcpHeader->th_dport < 1024 ? 3 : 1;// well-known ports weght more
              n_ptr->ports.insert(tcpHeader->th_dport);
              n_ptr->port_count = n_ptr->ports.size();
              n_ptr->flags = tcpHeader->th_flags;
              n_ptr->protocol = IPPROTO_TCP;
            }
          }
        }
      }
    }
  }
  else
  {
    ++other_quant;
  }

  return;
}


void print_packetInfo(const u_char *packet, int size)
{
  struct ether_header* ethernetHeader;
  ethernetHeader = (struct ether_header*) packet;
  char* sourceMAC = ether_ntoa((struct ether_addr*)ethernetHeader->ether_shost);//better print right away
  char* destMAC = ether_ntoa((struct ether_addr*)ethernetHeader->ether_dhost);

  struct ip* ipHeader;
  ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
  char sourceIP[INET_ADDRSTRLEN];
  char destIP[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);//AF_INET for IPv4 protocol
  inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);

  return;
}

void runOffline(const char* filename)
{
  pcap_t *pcap_file;
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_file = pcap_open_offline(filename, errbuf);
  if(pcap_file == NULL)
  {
    printf("pcap_open_offline() failed: %s\n", errbuf);
    return;
  }

  if(pcap_loop(pcap_file, 0, packetHandler, NULL) < 0)// NULL is the first argument passed into packetHandler
  {
    printf("pcap_loop() failed: %s\n", pcap_geterr(pcap_file));
    return;
  }

  for(auto it = hosts.begin(); it != hosts.end(); ++it)
  {
    if(it->second.scan_weight > 21 && it->second.scan_delay_avg/it->second.ports.size() < SCAN_DELAY){//just random number
      char sourceIP[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &(it->second.ip_src), sourceIP, INET_ADDRSTRLEN);//AF_INET for IPv4 protocol
      char destIP[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &(it->second.ip_dst), destIP, INET_ADDRSTRLEN);
      if(it->second.protocol == IPPROTO_UDP)
      {
        printf("Possible UDP scan detected from %s to %s\n", sourceIP, destIP);
        printf("From port:#{%d} to %d number of ports:\n", it->second.source_port, it->second.ports.size());
        printf("--------------\n");
        udp_scans += it->second.ports.size();

        for(auto j = it->second.ports.begin(); j != it->second.ports.end(); ++j)
        {
          printf("%d\/ ", *j);
        }
        printf("\n");
        printf("--------------\n");
        for(auto n_ptr = it->second.next; n_ptr != nullptr; n_ptr = n_ptr->next)
        {
          char nextIP[INET_ADDRSTRLEN];
          inet_ntop(AF_INET, &(n_ptr->ip_dst), nextIP, INET_ADDRSTRLEN);
          if(n_ptr->protocol == IPPROTO_UDP)
          {
            printf("Possible UDP scan detected from %s to %s\n", sourceIP, nextIP);
            printf("From port:#{%d} to %d number of ports:\n", n_ptr->source_port, n_ptr->ports.size());
            udp_scans += n_ptr->ports.size();
            for(auto j = n_ptr->ports.begin(); j != n_ptr->ports.end(); ++j)
            {
              printf("%d\/ ", *j);
            }
            printf("\n");
            printf("--------------\n");
          }
          else if(n_ptr->protocol == IPPROTO_TCP)
          {
            printf("Possible tcp scan detected from %s to %s\n", sourceIP, nextIP);
            printf("From port:#{%d} to %d number of ports:\n", n_ptr->source_port, n_ptr->ports.size());
            tcp_scans += n_ptr->ports.size();
            switch(n_ptr->flags){
              case 0x29:
                xmas_scans += n_ptr->ports.size();
                printf("Possible Type of the scan: XMAS-scan");
                break;
              case 0x00:
                null_scans += n_ptr->ports.size();
                printf("Possible Type of the scan: NULL-scan");
                break;
              case 0x02:
                halfopen_scans += n_ptr->ports.size();
                printf("Possible Type of the scan: Syn|Half-open|-scan");
                break;
              default: break;
            }
            for(auto j = n_ptr->ports.begin(); j != n_ptr->ports.end(); ++j)
            {
              printf("%d\/ ", *j);
            }
            printf("\n");
            printf("--------------\n");
          }
        }
      }
      else if(it->second.protocol == IPPROTO_TCP)
      {
        printf("Possible TCP scan detected from %s to %s\n", sourceIP, destIP);
        printf("From port:#{%d} to %d number of ports:\n", it->second.source_port, it->second.ports.size());
        tcp_scans += it->second.ports.size();
        switch(it->second.flags)
        {
          case 0x29:
            xmas_scans += it->second.ports.size();
            printf("Possible Type of the scan: XMAS-scan");
            break;
          case 0x00:
            null_scans += it->second.ports.size();
            printf("Possible Type of the scan: NULL-scan");
            break;
          case 0x02:
            halfopen_scans += it->second.ports.size();
            printf("Possible Type of the scan: Syn|Half-open|-scan");
            break;
          default: break;
        }
        printf("--------------\n");

        for(auto j = it->second.ports.begin(); j != it->second.ports.end(); ++j)
        {
          printf("%d\/ ", *j);
        }
        printf("\n");
        printf("--------------\n");
        for(auto n_ptr = it->second.next; n_ptr != nullptr; n_ptr = n_ptr->next)
        {
          char nextIP[INET_ADDRSTRLEN];
          inet_ntop(AF_INET, &(n_ptr->ip_dst), nextIP, INET_ADDRSTRLEN);
          if(n_ptr->protocol == IPPROTO_TCP)
          {
            printf("Possible tcp scan detected from %s to %s\n", sourceIP, nextIP);
            printf("From port:#{%d} to %d number of ports:\n", n_ptr->source_port, n_ptr->ports.size());
            tcp_scans += n_ptr->ports.size();
            switch(n_ptr->flags){
              case 0x29:
                xmas_scans += n_ptr->ports.size();
                printf("Possible Type of the scan: XMAS-scan");
                break;
              case 0x00:
                null_scans += n_ptr->ports.size();
                printf("Possible Type of the scan: NULL-scan");
                break;
              case 0x02:
                halfopen_scans += n_ptr->ports.size();
                printf("Possible Type of the scan: Syn|Half-open|-scan");
                break;
              default: break;
            }
            for(auto j = n_ptr->ports.begin(); j != n_ptr->ports.end(); ++j)
            {
              printf("%d\/ ", *j);
            }
            printf("\n");
            printf("--------------\n");
          }
          else if(n_ptr->protocol == IPPROTO_UDP)
          {
            printf("Possible UDP scan detected from %s to %s\n", sourceIP, nextIP);
            printf("From port:#{%d} to %d number of ports:\n", n_ptr->source_port, n_ptr->ports.size());
            udp_scans += n_ptr->ports.size();
            for(auto j = n_ptr->ports.begin(); j != n_ptr->ports.end(); ++j)
            {
              printf("%d\/ ", *j);
            }
            printf("\n");
            printf("--------------\n");
        }
      }
    }
  }



  //Summary
  printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
  printf("*%s* packet summary\n", filename);
  printf("Total number of packets: %d\n", total_quant);
  printf("----------------------------------------\n");
  printf("Number of possible icmp packets: %d\n", icmp_quant);
  printf("Number of possible icmp requests(pings): %d\n", icmp_requests);
  printf("----------------------------------------\n");
  printf("Number of possible udp packets: %d\n", udp_quant);
  printf("Number of possible udp scans: %d\n", udp_scans);
  printf("----------------------------------------\n");
  printf("Number of possible tcp packets: %d\n", tcp_quant);
  printf("Number of possible tcp scans: %d\n", tcp_scans);
  printf("----------------------------------------\n");
  printf("Number of other packets: %d\n", other_quant);
  printf("************************************************************\n");
  printf("Offline mode finished\n");
  hosts.clear();
  return;
}
}
//null_scans, xmas_scans, udp_scans, icmp_requests, halfopen_scans;
//total_quant, tcp_quant, icmp_quant, udp_quant, other_quant;
void runOnline()
{
  return;
}
