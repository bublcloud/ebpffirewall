#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <iproute2/bpf_elf.h>
#include "../libbpf/src/bpf_helpers.h"

//#include "include/xdpfw.h"

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) ((__be16)___constant_swab16((x)))
#define ntohs(x) ((__be16)___constant_swab16((x)))
#define htonl(x) ((__be32)___constant_swab32((x)))
#define ntohl(x) ((__be32)___constant_swab32((x)))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htons(x) (x)
#define ntohs(X) (x)
#define htonl(x) (x)
#define ntohl(x) (x)
#endif
// #define uint128_t __uint128_t

// BPF_TABLE("percpu_array", uint32_t, long, packetcnt, 256);

// struct bpf_elf_map SEC("maps") r_map = {
//     .type           = BPF_MAP_TYPE_ARRAY,
//     .size_key       = sizeof(uint32_t),
//     .size_value     = sizeof(uint32_t),
//     .pinning        = PIN_GLOBAL_NS,
//     .max_elem       = 65000,
// };

struct bublr {
    uint32_t sip0;
    uint32_t sip1;
    uint32_t sip2;
    uint32_t sip3;
    uint32_t dip0;
    uint32_t dip1;
    uint32_t dip2;
    uint32_t dip3;
    uint8_t dmac0;
    uint8_t dmac1;
    uint8_t dmac2;
    uint8_t dmac3;
    uint8_t dmac4;
    uint8_t dmac5;
    uint16_t pad;
};

struct distdestr {
    uint32_t dip0;
    uint32_t dip1;
    uint32_t dip2;
    uint32_t dip3;
    uint8_t dmac0;
    uint8_t dmac1;
    uint8_t dmac2;
    uint8_t dmac3;
    uint8_t dmac4;
    uint8_t dmac5;
    uint16_t pad;
};

struct distsourcer {
    uint32_t sip0;
    uint32_t sip1;
    uint32_t sip2;
    uint32_t sip3;
};




struct bpf_map_def SEC("maps") xdp_rule_map =
{
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct bublr),
    .value_size = sizeof(uint32_t),
    .max_entries = 65536,
};


// struct bpf_map_def SEC("maps") xdp_gateway_map =
// {
//     .type = BPF_MAP_TYPE_HASH,
//     .key_size = sizeof(uint32_t),
//     .value_size = sizeof(uint32_t),
//     .max_entries = 1000,
// };

struct bpf_map_def SEC("maps") xdp_distdest_map =
{
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct distdestr),
    .value_size = sizeof(uint32_t),
    .max_entries = 65536,
};

struct bpf_map_def SEC("maps") xdp_distsource_map =
{
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct distsourcer),
    .value_size = sizeof(uint32_t),
    .max_entries = 65536,
};

SEC("xdp_prog")
int xdp_prog_main(struct xdp_md *ctx) {
  int ipsize = 0;
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *ethhdr = data;
  struct iphdr *ip;
  struct ipv6hdr *iph6;
  // uint128_t srcip6 = 0;
  int ipp1 = 0;
  int ipp2 = 0;
  int ipp3 = 0;
  int ipp4 = 0;
  int ipp5 = 0;
  int ipp6 = 0;
  int ipp7 = 0;
  int ipp8 = 0;
  int dport = 0;
  int sport = 0;
  //long *cnt;
  struct tcphdr *tcph = NULL;
  // struct udphdr *udph = NULL;
  struct icmp6hdr *icmp6h = NULL;
  __u32 idx;
  __u16 h_proto;
  // const uint32_t icmpbasesource = htons((uint32_t)strtol("fe80", NULL, 16));
  //char dtxt[] = "ip %d\n";
  //uint64_t nh_off = 0;

  ipsize = sizeof(*ethhdr);
  ip = data + ipsize;
  ipsize += sizeof(struct iphdr);

  if (data + ipsize > data_end) {
    return XDP_DROP;
  }

  idx = ip->protocol;
  h_proto = ethhdr->h_proto;
  char schar[] = "Package coming in %d\n";
  char tchar[] = "Type %d\n";
  char rchar[] = "Match %d\n";

  if (h_proto == htons(ETH_P_IPV6)) {
    iph6 = (data + sizeof(struct ethhdr));

    if (unlikely(iph6 + 1 > (struct ipv6hdr *)data_end))
    {
      return XDP_DROP;
    }
    // srcip6 |= (uint128_t) iph6->saddr.in6_u.u6_addr32[0] << 0;
    // srcip6 |= (uint128_t) iph6->saddr.in6_u.u6_addr32[1] << 32;
    // srcip6 |= (uint128_t) iph6->saddr.in6_u.u6_addr32[2] << 64;
    // srcip6 |= (uint128_t) iph6->saddr.in6_u.u6_addr32[3] << 96;

   
   
    ipp1 = ntohs(iph6->saddr.in6_u.u6_addr16[0]);
    ipp2 = ntohs(iph6->saddr.in6_u.u6_addr16[1]);
    ipp3 = ntohs(iph6->saddr.in6_u.u6_addr16[2]);
    ipp4 = ntohs(iph6->saddr.in6_u.u6_addr16[3]);
    ipp5 = ntohs(iph6->saddr.in6_u.u6_addr16[4]);
    ipp6 = ntohs(iph6->saddr.in6_u.u6_addr16[5]);
    ipp7 = ntohs(iph6->saddr.in6_u.u6_addr16[6]);
    ipp8 = ntohs(iph6->saddr.in6_u.u6_addr16[7]);
  
   
    bpf_trace_printk(schar, sizeof(schar), 1);
    char ips_str[] = "sip%d %x\n";
    bpf_trace_printk(ips_str, sizeof(ips_str), 1, ipp1);
    bpf_trace_printk(ips_str, sizeof(ips_str), 2, ipp2);
    bpf_trace_printk(ips_str, sizeof(ips_str), 3, ipp3);
    bpf_trace_printk(ips_str, sizeof(ips_str), 4, ipp4);
    bpf_trace_printk(ips_str, sizeof(ips_str), 5, ipp5);
    bpf_trace_printk(ips_str, sizeof(ips_str), 6, ipp6);
    bpf_trace_printk(ips_str, sizeof(ips_str), 7, ipp7);
    bpf_trace_printk(ips_str, sizeof(ips_str), 8, ipp8);
    bpf_trace_printk(schar, sizeof(schar), 2);
    char ipd_str[] = "dip%d %x\n";
    bpf_trace_printk(ipd_str, sizeof(ipd_str), 1, ntohs(iph6->daddr.in6_u.u6_addr16[0]));
    bpf_trace_printk(ipd_str, sizeof(ipd_str), 2, ntohs(iph6->daddr.in6_u.u6_addr16[1]));
    bpf_trace_printk(ipd_str, sizeof(ipd_str), 3, ntohs(iph6->daddr.in6_u.u6_addr16[2]));
    bpf_trace_printk(ipd_str, sizeof(ipd_str), 4, ntohs(iph6->daddr.in6_u.u6_addr16[3]));
    bpf_trace_printk(ipd_str, sizeof(ipd_str), 5, ntohs(iph6->daddr.in6_u.u6_addr16[4]));
    bpf_trace_printk(ipd_str, sizeof(ipd_str), 6, ntohs(iph6->daddr.in6_u.u6_addr16[5]));
    bpf_trace_printk(ipd_str, sizeof(ipd_str), 7, ntohs(iph6->daddr.in6_u.u6_addr16[6]));
    bpf_trace_printk(ipd_str, sizeof(ipd_str), 8, ntohs(iph6->daddr.in6_u.u6_addr16[7]));

    bpf_trace_printk(schar, sizeof(schar), 3);

    char eth_s_char[] = "Es%d %x\n";
    bpf_trace_printk(eth_s_char, sizeof(eth_s_char), 1, ethhdr->h_source[0]);
    bpf_trace_printk(eth_s_char, sizeof(eth_s_char), 2, ethhdr->h_source[1]);
    bpf_trace_printk(eth_s_char, sizeof(eth_s_char), 3, ethhdr->h_source[2]);
    bpf_trace_printk(eth_s_char, sizeof(eth_s_char), 4, ethhdr->h_source[3]);
    bpf_trace_printk(eth_s_char, sizeof(eth_s_char), 5, ethhdr->h_source[4]);
    bpf_trace_printk(eth_s_char, sizeof(eth_s_char), 6, ethhdr->h_source[5]);

    char eth_d_char[] = "Ed%d %x\n";
    bpf_trace_printk(eth_d_char, sizeof(eth_d_char), 1, ethhdr->h_dest[0]);
    bpf_trace_printk(eth_d_char, sizeof(eth_d_char), 2, ethhdr->h_dest[1]);
    bpf_trace_printk(eth_d_char, sizeof(eth_d_char), 3, ethhdr->h_dest[2]);
    bpf_trace_printk(eth_d_char, sizeof(eth_d_char), 4, ethhdr->h_dest[3]);
    bpf_trace_printk(eth_d_char, sizeof(eth_d_char), 5, ethhdr->h_dest[4]);
    bpf_trace_printk(eth_d_char, sizeof(eth_d_char), 6, ethhdr->h_dest[5]);


    bpf_trace_printk(tchar, sizeof(tchar), iph6->nexthdr);
    if (iph6->nexthdr == IPPROTO_TCP) {
     tcph = (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));

     // Check TCP header.
     if (tcph + 1 > (struct tcphdr *)data_end)
     {
       return XDP_DROP;
     }
     bpf_trace_printk(schar, sizeof(schar), 5);
     char tcpport_str[] = "TCP port %d %d\n";
     sport = ntohs(tcph->source);
     dport = ntohs(tcph->dest);
     bpf_trace_printk(tcpport_str, sizeof(tcpport_str), 1, sport);
     bpf_trace_printk(tcpport_str, sizeof(tcpport_str), 2, dport);

     uint32_t *value;

     if (tcph->source == htons(443) && tcph->dest >= htons(32768)) {
      struct distsourcer distdestkey;
      distdestkey.sip0 = iph6->daddr.in6_u.u6_addr32[0];
      distdestkey.sip1 = iph6->daddr.in6_u.u6_addr32[1];
      distdestkey.sip2 = iph6->daddr.in6_u.u6_addr32[2];
      distdestkey.sip3 = iph6->daddr.in6_u.u6_addr32[3];

      value = bpf_map_lookup_elem(&xdp_distsource_map, &distdestkey);
      if (value) {
          bpf_trace_printk(rchar, sizeof(rchar), 1);
          return XDP_PASS;
      }
    }

     struct distsourcer distsourcekey;
     distsourcekey.sip0 = iph6->saddr.in6_u.u6_addr32[0];
     distsourcekey.sip1 = iph6->saddr.in6_u.u6_addr32[1];
     distsourcekey.sip2 = iph6->saddr.in6_u.u6_addr32[2];
     distsourcekey.sip3 = iph6->saddr.in6_u.u6_addr32[3];
     
     value = bpf_map_lookup_elem(&xdp_distsource_map, &distsourcekey);

     if (value) {
        struct distdestr distdestkey;
        distdestkey.dip0 = iph6->daddr.in6_u.u6_addr32[0];
        distdestkey.dip1 = iph6->daddr.in6_u.u6_addr32[1];
        distdestkey.dip2 = iph6->daddr.in6_u.u6_addr32[2];
        distdestkey.dip3 = iph6->daddr.in6_u.u6_addr32[3];
        distdestkey.dmac0 = ethhdr->h_dest[0];
        distdestkey.dmac1 = ethhdr->h_dest[1];
        distdestkey.dmac2 = ethhdr->h_dest[2];
        distdestkey.dmac3 = ethhdr->h_dest[3];
        distdestkey.dmac4 = ethhdr->h_dest[4];
        distdestkey.dmac5 = ethhdr->h_dest[5];
        distdestkey.pad = 0;

        value = bpf_map_lookup_elem(&xdp_distdest_map, &distdestkey);
         if (value) {
           bpf_trace_printk(rchar, sizeof(rchar), 1);
          return XDP_PASS;

         }

         bpf_trace_printk(rchar, sizeof(rchar), 2);
          return XDP_DROP;
      }

     
      struct bublr key;
      key.sip0 = iph6->saddr.in6_u.u6_addr32[0];
      key.sip1 = iph6->saddr.in6_u.u6_addr32[1];
      key.sip2 = iph6->saddr.in6_u.u6_addr32[2];
      key.sip3 = iph6->saddr.in6_u.u6_addr32[3];
      key.dip0 = iph6->daddr.in6_u.u6_addr32[0];
      key.dip1 = iph6->daddr.in6_u.u6_addr32[1];
      key.dip2 = iph6->daddr.in6_u.u6_addr32[2];
      key.dip3 = iph6->daddr.in6_u.u6_addr32[3];
      key.dmac0 = ethhdr->h_dest[0];
      key.dmac1 = ethhdr->h_dest[1];
      key.dmac2 = ethhdr->h_dest[2];
      key.dmac3 = ethhdr->h_dest[3];
      key.dmac4 = ethhdr->h_dest[4];
      key.dmac5 = ethhdr->h_dest[5];
      key.pad = 0;


      value = bpf_map_lookup_elem(&xdp_rule_map, &key);

      
      if (value) {
        bpf_trace_printk(rchar, sizeof(rchar), 1);
        return XDP_PASS;
      }
      bpf_trace_printk(rchar, sizeof(rchar), 2);
      return XDP_DROP;
    
    }

    // else if (iph6->nexthdr == IPPROTO_UDP) {
    //  udph = (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));

    //  // Check UDP header.
    //  if (udph + 1 > (struct udphdr *)data_end)
    //  {
    //    return XDP_DROP;
    //  }
    //  bpf_trace_printk(schar, sizeof(schar), 6);
    //  char udpport_str[] = "UDP port %d %d\n";
    //  sport = ntohs(udph->source);
    //  dport = ntohs(udph->dest);
    //  bpf_trace_printk(udpport_str, sizeof(udpport_str), 1, sport);
    //  bpf_trace_printk(udpport_str, sizeof(udpport_str), 2, dport);
    
    // }

    else if (iph6->nexthdr == IPPROTO_ICMPV6) {
     icmp6h = (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));

     // Check ICMPv6 header.
     if (icmp6h + 1 > (struct icmp6hdr *)data_end)
      {
      return XDP_DROP;
      }
     bpf_trace_printk(schar, sizeof(schar), 6);
     char icmptype_str[] = "ICMP type %d\n";
     bpf_trace_printk(icmptype_str, sizeof(icmptype_str), icmp6h->icmp6_type);
     char icmpcode_str[] = "ICMP code %d\n";
     bpf_trace_printk(icmpcode_str, sizeof(icmpcode_str), icmp6h->icmp6_code);


     if (icmp6h->icmp6_type == 1 || icmp6h->icmp6_type == 2 || (icmp6h->icmp6_type == 3 && icmp6h->icmp6_code == 0) || (icmp6h->icmp6_type == 4 && icmp6h->icmp6_code == 1) || (icmp6h->icmp6_type == 4 && icmp6h->icmp6_code == 2)  || icmp6h->icmp6_type == 136 || icmp6h->icmp6_type == 135) {


      bpf_trace_printk(rchar, sizeof(rchar), 1);
      return XDP_PASS;
      // if (iph6->saddr.in6_u.u6_addr16[0] ==  icmpbasesource ) {
      //     bpf_trace_printk(rchar, sizeof(rchar), 1);
      //     return XDP_PASS;
      // }    

      //   uint32_t *value;
      //   // struct gatewayr key;

      // uint32_t key;
      // key  = iph6->saddr.in6_u.u6_addr32[0];
      //   // key.sip0 = iph6->saddr.in6_u.u6_addr32[0];
      //   // key.sip1 = iph6->saddr.in6_u.u6_addr32[1];
      //   // key.sip2 = iph6->saddr.in6_u.u6_addr32[2];
      //   // key.sip3 = iph6->saddr.in6_u.u6_addr32[3];

      // value = bpf_map_lookup_elem(&xdp_gateway_map, &key);

        
      //   if (value) {
      //     bpf_trace_printk(rchar, sizeof(rchar), 1);
      //     return XDP_PASS;
      //   }

    }
    bpf_trace_printk(rchar, sizeof(rchar), 2);
    return XDP_DROP;


    
    }


  }

  // if (ip->protocol == IPPROTO_TCP) {
  //   return XDP_PASS;
    
  // }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
