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
#include <sys/types.h>
#include <vector>
#include <set>
// -lpcap flag
#define SCAN_DELAY 3
#define PORT_CHANGE 0xff
//should find a way to record host data to detect possible scans, mb use mapping or hashing structure to save hosts
struct port_connection
{
  unsigned short source_port;
  std::set<unsigned short> ports;
  int scan_weight;
  unsigned char flags;
  unsigned char flags_or;
  clock_t time_update;
  time_t create_time;
  clock_t scan_delay_avg;
};
struct host
{
  host* next; // if same ip_src, but different ip_dst;; for future implementations
  struct in_addr ip_src, ip_dst;
  unsigned int protocol;// UDP||ICMP||TCP
  std::vector<port_connection> connections;

  clock_t time_update;
  time_t create_time;
  clock_t scan_delay_avg;

  //int port_count;
  //  unsigned short source_port;
  //  std::set<unsigned short> ports;
  //unsigned char flags;
  //unsigned char flags_or; //TCP flags from dest|| urg/ack/psh/rst/syn/fin || 00111111|| xmas = 00101001 || fin = 00000001 || null = 00000000
  //|| half-open = 00010110 or 000000010 || if rst/ack or syn/ack or just rst then outgoing packet

};

//mb add filename to logfiles???
//FILE* icmp_logfile;
//FILE* tcp_logfile;
//FILE* udp_logfile;

int total_quant, tcp_quant, icmp_quant, udp_quant, other_quant;
int null_scans, xmas_scans, udp_scans, tcp_scans, icmp_requests, halfopen_scans;

std::unordered_map<unsigned int, host> ICMPhosts;//for easy access of the host
std::unordered_map<unsigned int, host> UDPhosts;//for easy access of the host
std::unordered_map<unsigned int, host> TCPhosts;//for easy access of the host

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

  struct tms buf;
  clock_t now;
  struct host current;
  struct port_connection current_port_connection;

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

    auto it = UDPhosts.find(ipHeader->ip_src.s_addr);

    if(it == UDPhosts.end()){
      current.time_update = now;
      current.create_time = time(NULL);
      current.ip_src = ipHeader->ip_src;
      current.ip_dst = ipHeader->ip_dst;
      current.protocol = IPPROTO_UDP;

      current_port_connection.time_update = now;
      current_port_connection.create_time = time(NULL);
      current_port_connection.source_port = ntohs(udpHeader->source);
      current_port_connection.ports.insert(ntohs(udpHeader->dest));
      current_port_connection.scan_weight = ntohs(udpHeader->dest) < 1024 ? 3 : 1;
      current_port_connection.flags = 0;
      current_port_connection.flags_or = 0;

      current.connections.push_back(current_port_connection);
      UDPhosts[ipHeader->ip_src.s_addr] = current;
    }
    else
    {
      if((it->second).ip_dst.s_addr != ipHeader->ip_dst.s_addr)
      {
        if(it->second.next == nullptr)
        {
          it->second.next = new host();
          it->second.next->time_update = now;
          it->second.next->create_time = time(NULL);
          it->second.next->ip_src = ipHeader->ip_src;
          it->second.next->ip_dst = ipHeader->ip_dst;
          it->second.next->protocol = IPPROTO_UDP;

          current_port_connection.time_update = now;
          current_port_connection.create_time = time(NULL);
          current_port_connection.source_port = ntohs(udpHeader->source);
          current_port_connection.ports.insert(ntohs(udpHeader->dest));
          current_port_connection.scan_weight = ntohs(udpHeader->dest) < 1024 ? 3 : 1;
          current_port_connection.flags = 0;
          current_port_connection.flags_or = 0;


          it->second.next->connections.push_back(current_port_connection);
        }
        else
        {
          for(auto n_ptr = it->second.next; n_ptr != nullptr; n_ptr = n_ptr->next)
          {
            if(n_ptr->ip_dst.s_addr != ipHeader->ip_dst.s_addr)
            {
              if(n_ptr->next == nullptr)
              {
                n_ptr->next = new host();
                n_ptr->next->time_update = now;
                n_ptr->next->create_time = time(NULL);
                n_ptr->next->ip_src = ipHeader->ip_src;
                n_ptr->next->ip_dst = ipHeader->ip_dst;
                n_ptr->next->protocol = IPPROTO_UDP;

                current_port_connection.time_update = now;
                current_port_connection.create_time = time(NULL);
                current_port_connection.source_port = ntohs(udpHeader->source);
                current_port_connection.ports.insert(ntohs(udpHeader->dest));
                current_port_connection.scan_weight = ntohs(udpHeader->dest) < 1024 ? 3 : 1;
                current_port_connection.flags = 0;
                current_port_connection.flags_or = 0;

                n_ptr->next->connections.push_back(current_port_connection);
                break;
              }
              else continue;
            }
            else
            {
              for(int i = 0; i < n_ptr->connections.size(); ++i)
              {
                if(n_ptr->connections[i].source_port == ntohs(udpHeader->source))
                {
                  n_ptr->connections[i].scan_delay_avg += now - n_ptr->connections[i].time_update;
                  n_ptr->connections[i].time_update = now;

                  auto insertion = n_ptr->connections[i].ports.insert(ntohs(udpHeader->dest));

                  if(insertion.second == true )n_ptr->connections[i].scan_weight += ntohs(udpHeader->dest) < 1024 ? 3 : 1;
                  break;
                }
                else if(i == n_ptr->connections.size() - 1)
                {
                  current_port_connection.time_update = now;
                  current_port_connection.create_time = time(NULL);
                  current_port_connection.source_port = ntohs(udpHeader->source);
                  current_port_connection.ports.insert(ntohs(udpHeader->dest));
                  current_port_connection.scan_weight = ntohs(udpHeader->dest) < 1024 ? 3 : 1;
                  current_port_connection.flags = 0;
                  current_port_connection.flags_or = 0;
                  n_ptr->connections.push_back(current_port_connection);
                  break;
                }
              }
              break;
            }
          }
        }
      }
      else
      {
        for(int i = 0; i < (it->second).connections.size(); ++i)
        {
          if((it->second).connections[i].source_port == ntohs(udpHeader->source))
          {
            (it->second).connections[i].scan_delay_avg += now - (it->second).connections[i].time_update;
            (it->second).connections[i].time_update = now;
            auto insertion = (it->second).connections[i].ports.insert(ntohs(udpHeader->dest));
            if(insertion.second == true) (it->second).connections[i].scan_weight += ntohs(udpHeader->dest) < 1024 ? 3 : 1;
            break;
          }
          else if(i == (it->second).connections.size() - 1)
          {
            current_port_connection.time_update = now;
            current_port_connection.create_time = time(NULL);
            current_port_connection.source_port = ntohs(udpHeader->source);
            current_port_connection.ports.insert(ntohs(udpHeader->dest));
            current_port_connection.scan_weight = ntohs(udpHeader->dest) < 1024 ? 3 : 1;
            current_port_connection.flags = 0;
            current_port_connection.flags_or = 0;
            it->second.connections.push_back(current_port_connection);
          }
        }
      }
    }
  }
  else if(ipHeader->ip_p == IPPROTO_TCP)
  {
    ++tcp_quant;
    struct tcphdr* tcpHeader;
    tcpHeader = (struct tcphdr*)(packet + sizeof(*ethernetHeader) + sizeof(*ipHeader));
    now = times(&buf);

    auto it = TCPhosts.find(ipHeader->ip_src.s_addr);

    if(it == TCPhosts.end()){
      current.time_update = now;
      current.create_time = time(NULL);
      current.ip_src = ipHeader->ip_src;
      current.ip_dst = ipHeader->ip_dst;
      current.protocol = IPPROTO_TCP;

      current_port_connection.time_update = now;
      current_port_connection.create_time = time(NULL);
      current_port_connection.source_port = ntohs(tcpHeader->th_sport);
      current_port_connection.ports.insert(ntohs(tcpHeader->th_dport));
      current_port_connection.scan_weight = ntohs(tcpHeader->th_dport) < 1024 ? 3 : 1;
      current_port_connection.flags = tcpHeader->th_flags;
      current_port_connection.flags_or = 0;

      current.connections.push_back(current_port_connection);
      TCPhosts[ipHeader->ip_src.s_addr] = current;
    }
    else
    {
      if((it->second).ip_dst.s_addr != ipHeader->ip_dst.s_addr)
      {
        if(it->second.next == nullptr)
        {
          it->second.next = new host();
          it->second.next->time_update = now;
          it->second.next->create_time = time(NULL);
          it->second.next->ip_src = ipHeader->ip_src;
          it->second.next->ip_dst = ipHeader->ip_dst;
          it->second.next->protocol = IPPROTO_TCP;

          current_port_connection.time_update = now;
          current_port_connection.create_time = time(NULL);
          current_port_connection.source_port = ntohs(tcpHeader->th_sport);
          current_port_connection.ports.insert(ntohs(tcpHeader->th_dport));
          current_port_connection.scan_weight = ntohs(tcpHeader->th_dport) < 1024 ? 3 : 1;
          current_port_connection.flags = tcpHeader->th_flags;
          current_port_connection.flags_or = 0;

          it->second.next->connections.push_back(current_port_connection);
        }
        else
        {
          for(auto n_ptr = it->second.next; n_ptr != nullptr; n_ptr = n_ptr->next)
          {
            if(n_ptr->ip_dst.s_addr != ipHeader->ip_dst.s_addr)
            {
              if(n_ptr->next == nullptr)
              {
                n_ptr->next = new host();
                n_ptr->next->time_update = now;
                n_ptr->next->create_time = time(NULL);
                n_ptr->next->ip_src = ipHeader->ip_src;
                n_ptr->next->ip_dst = ipHeader->ip_dst;
                n_ptr->next->protocol = IPPROTO_TCP;

                current_port_connection.time_update = now;
                current_port_connection.create_time = time(NULL);
                current_port_connection.source_port = ntohs(tcpHeader->th_sport);
                current_port_connection.ports.insert(ntohs(tcpHeader->th_dport));
                current_port_connection.scan_weight = ntohs(tcpHeader->th_dport) < 1024 ? 3 : 1;
                current_port_connection.flags = tcpHeader->th_flags;
                current_port_connection.flags_or = 0;

                n_ptr->next->connections.push_back(current_port_connection);
                break;
              }
              else continue;
            }
            else
            {
              for(int i = 0; i < n_ptr->connections.size(); ++i)
              {
                if(n_ptr->connections[i].source_port == ntohs(tcpHeader->source))
                {
                  n_ptr->connections[i].scan_delay_avg += now - n_ptr->connections[i].time_update;
                  n_ptr->connections[i].time_update = now;
                  auto insertion = n_ptr->connections[i].ports.insert(ntohs(tcpHeader->th_dport));
                  if(insertion.second == true) n_ptr->connections[i].scan_weight += ntohs(tcpHeader->th_dport) < 1024 ? 3 : 1;
                  break;
                }
                else if(i == n_ptr->connections.size() - 1)
                {
                  current_port_connection.time_update = now;
                  current_port_connection.create_time = time(NULL);
                  current_port_connection.source_port = ntohs(tcpHeader->th_sport);
                  current_port_connection.ports.insert(ntohs(tcpHeader->th_dport));
                  current_port_connection.scan_weight = ntohs(tcpHeader->th_dport) < 1024 ? 3 : 1;
                  current_port_connection.flags = tcpHeader->th_flags;
                  current_port_connection.flags_or = 0;
                  n_ptr->connections.push_back(current_port_connection);
                  break;
                }
              }
              break;
            }
          }
        }
      }
      else
      {
        for(int i = 0; i < (it->second).connections.size(); ++i)
        {
          if((it->second).connections[i].source_port == ntohs(tcpHeader->th_sport))
          {
            (it->second).connections[i].scan_delay_avg += now - (it->second).connections[i].time_update;
            (it->second).connections[i].time_update = now;
            auto insertion = (it->second).connections[i].ports.insert(ntohs(tcpHeader->th_dport));
            if(insertion.second == true) (it->second).connections[i].scan_weight += ntohs(tcpHeader->th_dport) < 1024 ? 3 : 1;
            break;
          }
          else if(i == (it->second).connections.size() - 1)
          {
            current_port_connection.time_update = now;
            current_port_connection.create_time = time(NULL);
            current_port_connection.source_port = ntohs(tcpHeader->th_sport);
            current_port_connection.ports.insert(ntohs(tcpHeader->th_dport));
            current_port_connection.scan_weight = ntohs(tcpHeader->th_dport) < 1024 ? 3 : 1;
            current_port_connection.flags = tcpHeader->th_flags;
            current_port_connection.flags_or = 0;
            it->second.connections.push_back(current_port_connection);
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

  for(auto it = UDPhosts.begin(); it != UDPhosts.end(); ++it)
  {
    char sourceIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(it->second.ip_src), sourceIP, INET_ADDRSTRLEN);//AF_INET for IPv4 protocol
    char destIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(it->second.ip_dst), destIP, INET_ADDRSTRLEN);
    for(int i = 0; i < it->second.connections.size(); ++i)
    {
      if(it->second.connections[i].scan_delay_avg >= 1 and it->second.connections[i].scan_weight >= 21 and it->second.connections[i].ports.size() >= 7 )
      {
        udp_scans += it->second.connections[i].ports.size();
        printf("UDP-scan detected...\n");
        printf("Source IP: %s =====================> Destination IP: %s\n", sourceIP, destIP);
        printf("Source port: %d =====================> ", it->second.connections[i].source_port);
        printf("Number of ports scanned: %d \n", it->second.connections[i].ports.size());
        printf("List of ports: \n");
      //  printf("scan_weight = %d, scan_delay = %d\n", it->second.connections[i].scan_weight, it->second.connections[i].scan_delay_avg);
        for(auto k = it->second.connections[i].ports.begin(); k != it->second.connections[i].ports.end(); ++k)
        {

          printf("%d ", *k);
        }
        printf("\n");
      }
    }
    if(it->second.next != nullptr)
    {
      for(auto n_ptr = it->second.next; n_ptr != nullptr; n_ptr = n_ptr->next)
      {
        inet_ntop(AF_INET, &(n_ptr->ip_dst), destIP, INET_ADDRSTRLEN);

        for(int i = 0; i < n_ptr->connections.size(); ++i)
        {
          if(n_ptr->connections[i].scan_delay_avg >= 1 and n_ptr->connections[i].scan_weight >= 21 and n_ptr->connections[i].ports.size() >= 7)
          {
            udp_scans += n_ptr->connections[i].ports.size();
            printf("UDP-scan detected...\n");
            printf("Source IP: %s =====================> Destination IP: %s\n", sourceIP, destIP);
            printf("Source port: %d =====================> ", n_ptr->connections[i].source_port);
            printf("Number of ports scanned: %d \n", n_ptr->connections[i].ports.size());
            printf("List of ports: \n");
//          printf("scan_weight = %d, scan_delay = %d\n", n_ptr->connections[i].scan_weight, n_ptr->connections[i].scan_delay_avg);
            for(auto k = n_ptr->connections[i].ports.begin(); k != n_ptr->connections[i].ports.end(); ++k)
            {
              printf("%d ", *k);
            }
            printf("\n");
          }

        }
      }
    }
  }
  printf("************************************************************\n");
  for(auto it = TCPhosts.begin(); it != TCPhosts.end(); ++it)
  {
    char sourceIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(it->second.ip_src), sourceIP, INET_ADDRSTRLEN);//AF_INET for IPv4 protocol
    char destIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(it->second.ip_dst), destIP, INET_ADDRSTRLEN);
    for(int i = 0; i < it->second.connections.size(); ++i)
    {
      char* scanType;
      if(it->second.connections[i].scan_delay_avg >= 1 and it->second.connections[i].scan_weight >= 21 and it->second.connections[i].ports.size() >= 7)
      {
        tcp_scans += it->second.connections[i].ports.size();
        switch(it->second.connections[i].flags){
          case 0x29:
            xmas_scans += it->second.connections[i].ports.size();
            scanType = "Xmas-scan";
            break;
          case 0x00:
            null_scans += it->second.connections[i].ports.size();
            scanType = "Null-scan";
            break;
          case 0x02:
            halfopen_scans += it->second.connections[i].ports.size();
            scanType = "Halfopen-scan";
            break;
          default: break;
        }
        printf("TCP-scan detected... Type: %s\n", scanType);
        printf("Source IP: %s =====================> Destination IP: %s\n", sourceIP, destIP);
        printf("Source port: %d =====================> ", it->second.connections[i].source_port);
        printf("Number of ports scanned: %d \n", it->second.connections[i].ports.size());
        printf("List of ports: \n");
      //  printf("scan_weight = %d, scan_delay = %d\n", it->second.connections[i].scan_weight, it->second.connections[i].scan_delay_avg);
        for(auto k = it->second.connections[i].ports.begin(); k != it->second.connections[i].ports.end(); ++k)
        {
          printf("%d ", *k);
        }
        printf("\n");
      }
    }
    if(it->second.next != nullptr)
    {
      for(auto n_ptr = it->second.next; n_ptr != nullptr; n_ptr = n_ptr->next)
      {
        inet_ntop(AF_INET, &(n_ptr->ip_dst), destIP, INET_ADDRSTRLEN);
        for(int i = 0; i < n_ptr->connections.size(); ++i)
        {
          char* scanType;
          if(n_ptr->connections[i].scan_delay_avg > SCAN_DELAY and n_ptr->connections[i].scan_weight >= 21 and n_ptr->connections[i].ports.size() >= 7)
          {
            tcp_scans += n_ptr->connections[i].ports.size();
            switch(n_ptr->connections[i].flags){
              case 0x29:
                xmas_scans += n_ptr->connections[i].ports.size();
                scanType = "Xmas-scan";
                break;
              case 0x00:
                null_scans += n_ptr->connections[i].ports.size();
                scanType = "Null-scan";
                break;
              case 0x02:
                halfopen_scans += n_ptr->connections[i].ports.size();
                scanType = "Halfopen-scan";
                break;
              default: break;
            }
            printf("TCP-scan detected... Type: %s\n", scanType);
            printf("Source IP: %s =====================> Destination IP: %s\n", sourceIP, destIP);
            printf("Source port: %d =====================> ", n_ptr->connections[i].source_port);
            printf("Number of ports scanned: %d \n", n_ptr->connections[i].ports.size());
            printf("List of ports: \n");
//          printf("scan_weight = %d, scan_delay = %d\n", n_ptr->connections[i].scan_weight, n_ptr->connections[i].scan_delay_avg);
            for(auto k = n_ptr->connections[i].ports.begin(); k != n_ptr->connections[i].ports.end(); ++k)
            {
              printf("%d ", *k);
            }
            printf("\n");
          }
        }
      }
  }
  }

  //Summary
  printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
  printf("*%s* packet summary\n", filename);
  printf("Total number of packets: %d\n", total_quant);
  printf("----------------------------------------\n");
  printf("Number of icmp packets: %d\n", icmp_quant);
  printf("Number of possible icmp requests(pings): %d\n", icmp_requests);
  printf("----------------------------------------\n");
  printf("Number of udp packets: %d\n", udp_quant);
  printf("Number of possible udp scans: %d\n", udp_scans);
  printf("----------------------------------------\n");
  printf("Number of tcp packets: %d\n", tcp_quant);
  printf("Number of possible tcp scans: %d\n", tcp_scans);
  printf("Number of possible null scans: %d\n", null_scans);
  printf("Number of possible xmas scans: %d\n", xmas_scans);
  printf("Number of possible halfopen-scans: %d\n", halfopen_scans);
  printf("----------------------------------------\n");
  printf("Number of other packets: %d\n", other_quant);
  printf("************************************************************\n");
  printf("Offline mode finished\n");
  TCPhosts.clear();
  UDPhosts.clear();
  return;
}

//null_scans, xmas_scans, udp_scans, icmp_requests, halfopen_scans;
//total_quant, tcp_quant, icmp_quant, udp_quant, other_quant;
void runOnline()
{
  return;
}
/* To be implemented for online mode
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
*/
