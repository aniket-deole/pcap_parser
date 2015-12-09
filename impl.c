#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap/pcap.h>
#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <unistd.h>
/*
 * Resources: 
 * http://www.tcpdump.org/pcap.html
 * http://www.tcpdump.org/manpages/pcap.3pcap.html
 * http://www.tcpdump.org/sniffex.c
 */
/* Packet Headers */

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
  u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
  u_short ether_type;                     /* IP? ARP? RARP? etc */
  //  u_char mm[16]; // for linux cooked interface
};

/* IP header */
struct sniff_ip {
  u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
  u_char  ip_tos;                 /* type of service */
  u_short ip_len;                 /* total length */
  u_short ip_id;                  /* identification */
  u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
  u_char  ip_ttl;                 /* time to live */
  u_char  ip_p;                   /* protocol */
  u_short ip_sum;                 /* checksum */
  struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
  u_short th_sport;               /* source port */
  u_short th_dport;               /* destination port */
  tcp_seq th_seq;                 /* sequence number */
  tcp_seq th_ack;                 /* acknowledgement number */
  u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
  u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short th_win;                 /* window */
  u_short th_sum;                 /* checksum */
  // u_short th_urp;                 /* urgent pointer */
  //       u_int seg_size;
  //       u_short tcp_sack;
  u_char pad1;
  u_char pad2;
  u_char nop;
  u_char nop2;
  u_char timestamp_kind;
  u_char timestamp_length;
  u_int timestamp_value;
  u_int echo_reply;
};

char errbuf[PCAP_ERRBUF_SIZE];

#define DATA_SOURCE_PORT 55002
#define ACK_SOURCE_PORT 25059 
#define START_PACKET 28415
#define END_PACKET 129000
#define PHONE_IP 66.87.137.204
//int part_6_start_indices[10] = { 4223, 7387, 10081, 12761, 17263, 20656, 25665, 30134, 
//  35267, 39977 };
int part_6_start_indices[10] = {
  28415, // 20
  40527, // 30
  52382, // 40
  61252, // 50
  68878, // 60
  80553, // 70
  89869, // 80
  96574, // 90
  107474,// 100
  117848// 110
};

int part_6_valid_count_choices[9] = {
  10,
  25,
  50,
  75,
  100,
  125,
  150,
  175,
  200,
};
int part_6_valid_count_choices_count = 9;
struct pkt_node {
  struct pcap_pkthdr* pn_pkt_hdr;
  char* pn_data;
  struct sniff_ethernet* pn_ethernet_hdr;
  struct sniff_ip* pn_ip_hdr;
  struct sniff_tcp* pn_tcp_hdr;
  struct pkt_node* next;
  int index;
};

struct pkt_node* pkt_list_head;
struct pkt_node* pkt_list_tail;

struct pkt_node* pkt_node_array;

int plh_i = 0;
void resolve_network_hdrs (struct pkt_node* node) {
  node->pn_ethernet_hdr = malloc (sizeof (struct sniff_ethernet));
  memcpy (node->pn_ethernet_hdr, node->pn_data, sizeof (struct sniff_ethernet));
  node->pn_ip_hdr = malloc (sizeof (struct sniff_ip));
  memcpy (node->pn_ip_hdr, node->pn_data + SIZE_ETHERNET, 
      sizeof (struct sniff_ip));
  node->pn_tcp_hdr = malloc (sizeof (struct sniff_tcp));
  memcpy (node->pn_tcp_hdr, node->pn_data + SIZE_ETHERNET + 
      sizeof (struct sniff_ip), sizeof (struct sniff_tcp));
  return;
}

void add_to_packet_list (struct pcap_pkthdr* pkt_hdr_p, char* data_p, int i) {
  if (pkt_list_head == NULL) {
    pkt_list_head = malloc (sizeof (struct pkt_node));
    pkt_list_head->index = i;
    pkt_list_head->pn_pkt_hdr = pkt_hdr_p;
    pkt_list_head->pn_data = data_p;
    pkt_list_head->next = NULL;
    pkt_list_tail = pkt_list_head;
  } else {
    struct pkt_node* node = malloc (sizeof (struct pkt_node));
    node->index = i;
    node->pn_pkt_hdr = pkt_hdr_p;
    node->pn_pkt_hdr = malloc (sizeof (struct pcap_pkthdr));
    memcpy (node->pn_pkt_hdr, pkt_hdr_p, sizeof (struct pcap_pkthdr));
    node->pn_data = malloc (sizeof (char) * node->pn_pkt_hdr->caplen);
    memcpy (node->pn_data, data_p, pkt_hdr_p->caplen);
    node->next = NULL;

    pkt_list_tail->next = node;
    pkt_list_tail = node;
  }
  resolve_network_hdrs (pkt_list_tail);
}

struct pkt_node* get_nth_packet (int n) {
  int i = 0;
  struct pkt_node* node = pkt_node_array + n;
  /* 
     if (plh == NULL) {
     node = pkt_list_head;
     if ( pkt_list_head_ten_sec == NULL) {
     while ( i < START_PACKET) {
     node = node->next;
     i++;
     }
     pkt_list_head_ten_sec = node;
     }
     i = 0;
     while ( i < n) {
     if ((ntohs (node->pn_tcp_hdr->th_sport)) != ACK_SOURCE_PORT) {
     node = node->next;
     i++;
     continue;
     }
     node = node->next;
     i++;
     if (node == NULL)
     return NULL;
     }
     if (node == NULL)
     return NULL;
     plh_i = n;
     } else {
     node = plh;
     }
     */
  while (ntohs (node->pn_tcp_hdr->th_sport) != ACK_SOURCE_PORT) {
    node = node->next;
    if (node == NULL)
      return NULL;
  }
  return node;
}

int get_start_index_g_for_ack (int n) {
  struct pkt_node* data_packet = pkt_list_head->next;
  while (1) {
    if (data_packet->index >= n) {
      if ((ntohs (data_packet->pn_tcp_hdr->th_sport)) == ACK_SOURCE_PORT) {
        data_packet = data_packet->next;
        continue;
      }
      break;
    }
    data_packet = data_packet->next;
  }
  tcp_seq seq_number = ntohl (data_packet->pn_tcp_hdr->th_seq);
  struct pkt_node* node = data_packet;

  while (1) {
    if ((ntohs (node->pn_tcp_hdr->th_sport)) == ACK_SOURCE_PORT) {
      tcp_seq ack = ntohl (node->pn_tcp_hdr->th_ack);
      if (ack >= seq_number)
        break;
    }
    if (node->next == NULL)
      break;
    node = node->next;
  }
  tcp_seq final_ack_number = ntohl (node->pn_tcp_hdr->th_ack);

  printf ("For Data Node: %d, Ack Node is %d\n", data_packet->index, node->index);

  return node->index;
}




float get_t4_minus_t0 (int start_index, int end) {
  struct pkt_node* ack = get_nth_packet (start_index);
  tcp_seq ack_number = ntohl (ack->pn_tcp_hdr->th_ack);
  struct pkt_node* node = get_nth_packet (start_index - 500);

  struct pkt_node* prev_data_node;
  while (1) {
    if ((ntohs (node->pn_tcp_hdr->th_sport)) != ACK_SOURCE_PORT) {
      tcp_seq seq = ntohl (node->pn_tcp_hdr->th_seq);
      prev_data_node = node;
      if (seq > ack_number)
        break;
    }
    if (node->next == NULL)
      break;
    node = node->next;
  }
  tcp_seq seq_number = ntohl (prev_data_node->pn_tcp_hdr->th_seq);
  printf ("Seq of Data Packet: %u\n",seq_number);
  struct timeval ts_one = prev_data_node->pn_pkt_hdr->ts;

  ack = get_nth_packet (end);
  ack_number = ntohl (ack->pn_tcp_hdr->th_ack);
  node = get_nth_packet (end - 500);

  prev_data_node = NULL;
  while (1) {
    if ((ntohs (node->pn_tcp_hdr->th_sport)) != ACK_SOURCE_PORT) {
      tcp_seq seq = ntohl (node->pn_tcp_hdr->th_seq);
      prev_data_node = node;
      if (seq > ack_number)
        break;
    }
    if (node->next == NULL)
      break;
    node = node->next;
  }
  seq_number = ntohl (prev_data_node->pn_tcp_hdr->th_seq);

  struct timeval difference;
  struct timeval ts_two = prev_data_node->pn_pkt_hdr->ts;
  int k = timeval_subtract (&difference, &ts_two, &ts_one);
  return difference.tv_usec / 1000.0 + difference.tv_sec * 1000;
}

int construct_pkt_list (char* filter) {
  pcap_t* dump_file = pcap_open_offline ("/home/aniket/projects/networks/pcap_parser/part8/aws_morning_fourth_filtered.pcap", errbuf);
  if (dump_file == NULL) {
    return -1;
  }

  char filter_exp[] = "tcp and ip host 66.87.137.204"; // PHONE_IP 
  struct bpf_program fp;

  if (!strcmp (filter, "NULL")) {
    if (pcap_compile (dump_file, &fp, filter_exp, 0, 0) == -1) {
      fprintf (stderr, "Error in pcap_compile.\n");
      exit (-1);
      return -1;
    }

    if (pcap_setfilter (dump_file, &fp) == -1) {
      fprintf (stderr, "Error in setting filter.\n");
      exit (-1);
      return -1;
    }
  }

  struct pcap_pkthdr* pkt_hdr_p;
  const u_char* data_p;
  int i = 0;
  while (pcap_next_ex (dump_file, &pkt_hdr_p, &data_p) == 1) {
    add_to_packet_list (pkt_hdr_p, (u_char*) data_p, i);
    i++;
  }
  fprintf (stdout, "Total TCP Packets: %d\n", i);


  pkt_node_array = malloc (sizeof (struct pkt_node) * i);

  int total_packets = i;
  struct pkt_node* node = pkt_list_head;
  for (i = 0; i < total_packets; i++) {
    memcpy (pkt_node_array + i, node, sizeof (struct pkt_node));
    node = node->next;
  }

  return 0;
}
/* Subtract the ‘struct timeval’ values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0. */

  int
timeval_subtract (result, x, y)
  struct timeval *result, *x, *y;
{
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (x->tv_usec - y->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}

int filter_based_on_time_milliseconds (int start_index, 
    float milliseconds, struct timeval* returnValue,
    float* ap) {
  struct pkt_node* node = get_nth_packet (start_index);
  struct timeval ts_one, ts_two;
  struct timeval bufTv, diff;
  diff.tv_sec = 0;
  diff.tv_usec = milliseconds * 1000;
  int payload = 0;
  int data_packets = 0;
  ts_one = node->pn_pkt_hdr->ts;
  bufTv = ts_one;
  timeradd (&ts_one, &diff, &ts_two);
  int i = start_index;
  while (node != NULL) {
    ts_one = node->pn_pkt_hdr->ts;
    if ((ntohs (node->pn_tcp_hdr->th_sport)) != ACK_SOURCE_PORT) {
      payload += node->pn_pkt_hdr->caplen;
      payload -= sizeof (struct sniff_ethernet);
      payload -= sizeof (struct sniff_ip);
      payload -= sizeof (struct sniff_tcp);
      node = node->next;
      i++;
      data_packets++;
      continue;
    }
    struct timeval returnValue; 
    int k = timeval_subtract (&returnValue, &ts_one, &bufTv);
    if (!timercmp (&returnValue, &diff, >)) {
      node = node->next;
      i++;
      continue;
    }
    break;

  }
  *ap = payload / (float) data_packets;
  int k = timeval_subtract (returnValue, &ts_one, &bufTv);
  return i;

}



int filter_based_on_time (int start_index, int seconds) {
  struct pkt_node* node = get_nth_packet (start_index);
  struct timeval ts_one, ts_two;
  time_t buf;
  struct timeval bufTv;
  bufTv = node->pn_pkt_hdr->ts;
  ts_one = node->pn_pkt_hdr->ts;
  buf = ts_one.tv_sec;
  ts_two = ts_one;
  ts_two.tv_sec += seconds;
  int i = start_index;
  int n_minus_two_packets = 0;
  while (node != NULL) {
    ts_one = node->pn_pkt_hdr->ts;
    if ((ntohs (node->pn_tcp_hdr->th_sport)) != ACK_SOURCE_PORT) {
      node = node -> next;
      i++;
      n_minus_two_packets++;
      continue;
    }
    if (timercmp (&ts_one, &ts_two, <)) {
      node = node->next;
      i++;
      continue;
    }
    break;
  }
  fprintf (stdout, "n-2: %d\n", n_minus_two_packets);
  fprintf (stdout, "Real deltaG: %d:%d:%d\n", ts_two.tv_sec, ts_one.tv_sec, ts_two.tv_sec - buf);
  struct timeval returnValue; 
  int k = timeval_subtract (&returnValue, &ts_two, &bufTv);
  return i;
}

struct pkt_node* get_n_minus_2th_packet (int start_index, int n) {
  struct pkt_node* node = get_nth_packet (start_index);
  int i = 0;
  while (node != NULL) {
    i++;
    node = node->next;
    if (i == (n-2))
      return node;
  }
  return NULL;
}

int get_data_packets_till (int start_index, int n) {
  struct pkt_node* node = get_nth_packet (start_index);
  fprintf (stdout, "t0: %d\n", node->pn_pkt_hdr->ts.tv_sec);
  int i = start_index; int j = 0;
  while (node != NULL) {
    if ((ntohs (node->pn_tcp_hdr->th_sport)) != ACK_SOURCE_PORT)
      j++;
    i++;
    node = node->next;
    if (i == (n-2)) {
      fprintf (stdout, "t4: %d\n", node->pn_pkt_hdr->ts.tv_sec);
      return j;
    }
  }
  return 0;
}

float C = 0.0f;
float W = 0.0f;
int K = 0;

// http://www.gnu.org/software/libc/manual/html_node/Example-of-Getopt.html#Example-of-Getopt
int parse_arguments (int argc, char** argv) {
  int aflag = 0;
  int bflag = 0;
  char *cvalue = NULL;
  int c;

  opterr = 0;
  while ((c = getopt (argc, argv, "c:k:w:p:")) != -1)
    switch (c)
    {
      case 'c':
        C = atof (optarg);
        break;
      case 'k':
        K = atoi (optarg);
        break;
      case 'w':
        W = atof (optarg);
        break;
      case '?':
        if (isprint (optopt))
          fprintf (stderr, "Unknown option `-%c'.\n", optopt);
        else
          fprintf (stderr,
              "Unknown option character `\\x%x'.\n",
              optopt);
        return 1;
      default:
        abort ();
    }
  if (C == 0.0)
    return 1;
  return 0;
}

int main (int argc, char** argv) {
  if (construct_pkt_list ("NULL")) {
    fprintf (stderr, "Error creating packet list.\n");
  }
  int start_index_g = START_PACKET;
  int big_window_size = 0;

  if (parse_arguments (argc, argv)) {
    exit (1);
  } 
  int deltaG = 3;
  int array_index_for_part_6 = 0;
  for (array_index_for_part_6 = 0; array_index_for_part_6 < 10; array_index_for_part_6++) {
    //    int packet_after_5_seconds = filter_based_on_time (
    //        part_6_start_indices[array_index_for_part_6], 5);
    printf ("ASI: %d\n", array_index_for_part_6);
    int part_6_valid_count_index = 0;

    for (;part_6_valid_count_index < 9; 
        part_6_valid_count_index++) {
      start_index_g =part_6_start_indices[array_index_for_part_6];
      printf ("VSI: %d\n", part_6_valid_count_index);
      int valid_counts_in_this_run = 0;
      for (; start_index_g <= END_PACKET; start_index_g++) {
      
        if (ntohs(pkt_node_array[start_index_g].pn_tcp_hdr->th_sport) != DATA_SOURCE_PORT) {
          continue;
        }
        
        printf ("SI: %d\n", start_index_g);
        
        int packet_after_deltaG_seconds = filter_based_on_time (start_index_g, deltaG);
        printf ("%d\n", packet_after_deltaG_seconds);
        
        struct pkt_node* node_one = get_nth_packet (start_index_g);
        struct pkt_node* node_two = get_nth_packet (packet_after_deltaG_seconds);
        
        float G = 0.0f;
        if (node_two == NULL) {
          G = 100.0f;
        } else {
          u_int TS1 = ntohl (node_one->pn_tcp_hdr->timestamp_value);
          u_int TS2 = ntohl (node_two->pn_tcp_hdr->timestamp_value);

          G = (TS2 - TS1) / (float) deltaG;
        }

        G = 1 / G;
        printf ("G: %f\n", G);
        
        // Calculation of G Finished.

        struct timeval actual_window;
        // [1]
        float average_payload = 0.0f;
        int k = filter_based_on_time_milliseconds(start_index_g, W, &actual_window, &average_payload);

        if (average_payload == 0.0f) {
          printf ("Average Payload received as 0.0.");
          exit (1);
        }
        if (k == 1) {
          printf ("K is one!");
        }
        float t4_t0_ms = get_t4_minus_t0 (start_index_g, k); 
        printf ("ValueOfK: %d\n", k); 
        // one = [1]
        int data_packets_till_one = get_data_packets_till (start_index_g,
            k);
        printf ("Data Packets after deltaG seconds: %d\n", data_packets_till_one);
        printf ("t4_minus_t0: %f\n", t4_t0_ms);
        float Rsnd = (average_payload* data_packets_till_one) / t4_t0_ms;
        Rsnd = (((Rsnd) / 1024) / 1024) * 8000; // Converting to mbps
        printf ("Rsnd: %f Mbits/sec\n", Rsnd); 

        if (Rsnd > C){
          struct pkt_node* node_one_p2 = get_nth_packet (start_index_g);
          struct pkt_node* node_two_p2 = get_nth_packet (k);
          u_int TS1_p2 = ntohl (node_one_p2->pn_tcp_hdr->timestamp_value);
          u_int TS2_p2 = ntohl (node_two_p2->pn_tcp_hdr->timestamp_value);


          float Rrcv = (average_payload* data_packets_till_one)/ 
            (G * (TS2_p2 - TS1_p2));
          Rrcv = Rrcv * 0.000008;
          printf ("Rrcv: %f Mbits/sec\n", Rrcv);
          printf ("RsndRrcv %d %f %f\n", data_packets_till_one, Rsnd, Rrcv);
          if (data_packets_till_one >= K) {
            printf ("RRWDPCMT10_%d_%d_%d %d %f %f\n", array_index_for_part_6, 
                part_6_valid_count_index,
                part_6_valid_count_choices[part_6_valid_count_index],
                data_packets_till_one, Rsnd, Rrcv);
            valid_counts_in_this_run++;
          }
          if (valid_counts_in_this_run == part_6_valid_count_choices[part_6_valid_count_index]) {
            printf ("VCINTRE_%d_%d %d\n", array_index_for_part_6,
                part_6_valid_count_index,valid_counts_in_this_run);
            break;
          }
        }
        printf ("FIN\n\n");
      }
    }
  }
  return 0;
}
