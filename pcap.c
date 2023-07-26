#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "ja3_from_pcap.h"

/* Parse the packet upto the TLS header */
static packet_parse_error_t get_tls_ptr (uint8_t const *bytes, int datalink,
					 unsigned pak_len,
					 uint8_t **ptr_tls_start,
					 unsigned *tls_len_max,
					 int *ptr_af,
					 uint8_t *ptr_src_addr,
					 uint8_t *ptr_dst_addr,
					 uint16_t *ptr_tcp_src_port) {
  uint8_t *cursor;
  uint8_t *sentinel;
  uint16_t ethertype, tcp_dport;
  uint8_t expected_ip_version, actual_ip_version, ver_ihl;
  uint8_t *tcp_header, l4_proto, tcp_header_len;

  cursor = (uint8_t *) bytes;
  sentinel = cursor + pak_len;

  expected_ip_version = 0;
  if (datalink == DLT_EN10MB) {
    if (!safe_get_bytes(&cursor, 12, 2, sentinel, &ethertype)) {
      return WOULD_EXCEED_BOUNDS;
    }
    ethertype = ntohs(ethertype);
    if (ethertype == 0x8100) { /* 802.1Q tag */
      /* Go past the 2-byte VLAN ID, then get the 2-byte ethertype that follows */
      if (!safe_get_bytes(&cursor, 2, 2, sentinel, &ethertype)) {
	return WOULD_EXCEED_BOUNDS;
      }
      ethertype = ntohs(ethertype);
      if (ethertype == 0x0800) {
	expected_ip_version = 4;
      } else if (ethertype == 0x86dd) {
	expected_ip_version = 6;
      } else {
	return UNKNOWN_ETHERTYPE;
      }
    }
  } else if (datalink == DLT_LINUX_SLL) {
    if (!safe_get_bytes(&cursor, 14, 2, sentinel, &ethertype)) {
      return WOULD_EXCEED_BOUNDS;
    }
    ethertype = ntohs(ethertype);
    if (ethertype == 0x8100) { /* 802.1Q tag */
      /* Go past the 2-byte VLAN ID, then get the 2-byte ethertype that follows */
      if (!safe_get_bytes(&cursor, 2, 2, sentinel, &ethertype)) {
	return WOULD_EXCEED_BOUNDS;
      }
      ethertype = ntohs(ethertype);
      if (ethertype == 0x0800) {
	expected_ip_version = 4;
      } else if (ethertype == 0x86dd) {
	expected_ip_version = 6;
      } else {
	return UNKNOWN_ETHERTYPE;
      }
    }
  } else if (datalink == DLT_RAW) {
    expected_ip_version = 0; /* = just use the actual version from the header */
  } else {
    return UNSUPPORTED_DATALINK_LAYER;
  }

  /* cursor should be at the first byte of the IPv4/IPv6 header */
  if (!safe_get_bytes(&cursor, 0, 1, sentinel, &ver_ihl)) {
    return WOULD_EXCEED_BOUNDS;
  }

  actual_ip_version = ver_ihl >> 4;

  /* If the header contained an ethertype field, see if the IP version specified
     by the ethertype matches the actual IP header version field. */
  if ((expected_ip_version != 0) && (actual_ip_version != expected_ip_version)) {
    return UNEXPECTED_FORMAT;
  }

  if (actual_ip_version == 6) { /* IPv6 */
    /* We've already gone past the Ver byte */
    /* Check the Next Header field */
    if (!safe_get_bytes(&cursor, 5, 1, sentinel, &l4_proto)) {
      return WOULD_EXCEED_BOUNDS;
    }
    if (l4_proto != 6) { /* Check TCP; no support for IPv6 Header Extensions */
      return UNEXPECTED_FORMAT;
    }
    
    *ptr_af = AF_INET6;
    if (!safe_get_bytes(&cursor, 1, 16, sentinel, ptr_src_addr)) {
      return WOULD_EXCEED_BOUNDS;
    }
    if (!safe_get_bytes(&cursor, 0, 16, sentinel, ptr_dst_addr)) {
      return WOULD_EXCEED_BOUNDS;
    }
    
    tcp_header = cursor;
  } else if (actual_ip_version == 4) { /* IPv4 */
    /* We've already gone past the Ver/IHL byte */
    /* Check the Protocol field */
    if (!safe_get_bytes(&cursor, 8, 1, sentinel, &l4_proto)) {
      return WOULD_EXCEED_BOUNDS;
    }

    if (l4_proto != 6) { /* Check TCP */
      return UNEXPECTED_FORMAT;
    }
    
    *ptr_af = AF_INET;
    if (!safe_get_bytes(&cursor, 2, 4, sentinel, ptr_src_addr)) {
      return WOULD_EXCEED_BOUNDS;
    }
    if (!safe_get_bytes(&cursor, 0, 4, sentinel, ptr_dst_addr)) {
      return WOULD_EXCEED_BOUNDS;
    }
    
    tcp_header = cursor - 20 + ((ver_ihl & (uint8_t) 0xf) << 2);
  } else { /* Unexpected IP version field */
    return UNEXPECTED_FORMAT;
  }

  /* If we got here, tcp_header should be set */
  
  /* Our PCAP filter filters for Destination Port == 443, but we'll double-check
     it now anyway to ensure that our header parsing logic is correct.
     TODO: REMOVE THIS */
  cursor = tcp_header;
  if (!safe_get_bytes(&cursor, 0, 2, sentinel, ptr_tcp_src_port)) {
    return WOULD_EXCEED_BOUNDS;
  }
  if (!safe_get_bytes(&cursor, 0, 2, sentinel, &tcp_dport)) {
    return WOULD_EXCEED_BOUNDS;
  }
  if (ntohs(tcp_dport) != 443) {
    return UNEXPECTED_FORMAT;
  }

  /* Go to the start of the tcp payload, i.e. the TLS header */
  
  if (!safe_get_bytes(&cursor, 8, 1, sentinel, &tcp_header_len)) {
    return WOULD_EXCEED_BOUNDS;
  }

  /*
     ....xxxx
     0000.... after >> 4
     00....00 after << 2
     00111100 mask
     >> 4, << 2 == >> 2
  */
  *ptr_tls_start = (cursor - 1 - 8 - 4 + ((tcp_header_len >> 2) & (uint8_t) 0x3c));

  if (*ptr_tls_start > sentinel) {
    /* This is an error. For the case that this is a bare ACK TCP packet, 
       *ptr_tls_start will be equal to sentinel. Or when there is TLS data,
       *ptr_tls_start will be less than sentinel. */
    return UNEXPECTED_FORMAT;
  }
  
  *tls_len_max = sentinel - *ptr_tls_start;
    
  return NO_PACKET_PARSE_ERROR; 
}

static char display_str[1024 + 1];
static char ts_str[128 + 1];

/* Helper to render the packet timestamp in the PCAP into a readable string */
static char *get_ts_str (const struct pcap_pkthdr *pkt) {
  time_t pkt_time;
  struct tm pkt_tm = {0};
  size_t ts_str_filled;

  pkt_time = pkt->ts.tv_sec;
  gmtime_r(&pkt_time, &pkt_tm);
  
  ts_str[128] = '\0';
  ts_str_filled = strftime(ts_str, 128, "%H:%M:%S", &pkt_tm);

  snprintf(&(ts_str[ts_str_filled]), 128 - ts_str_filled, ".%06ld",
	   pkt->ts.tv_usec);

  return &(ts_str[0]);
}

/*
 * Callback invoked from pcap_loop(), for every packet with tcp dest port == 443
 */
static void tcp_dport_443_handler (uint8_t *user, const struct pcap_pkthdr *pkt,
                                   const uint8_t *bytes) {
  pcap_packet_context_t *pak_ctxt = (pcap_packet_context_t *) user;
  unsigned tls_len_max = 0;
  packet_parse_error_t err;
  uint8_t *ptr_tls;
  struct errored_packet_t_ *err_pkt;
  int af;
  uint8_t src_addr[16];
  uint8_t dst_addr[16];
  uint16_t tcp_src_port;
  char src_addr_str[INET6_ADDRSTRLEN];
  char dst_addr_str[INET6_ADDRSTRLEN];
  char md5_hash_str[32 + 1];

  /* Bump up the packet ordinal */
  pak_ctxt->packet_ord++;

  /* Obtain the start of the TLS header, and if that is successful get the JA3 */
  ptr_tls = 0;
  err = get_tls_ptr(bytes, pak_ctxt->datalink, pkt->caplen, &ptr_tls, &tls_len_max,
		    &af, &(src_addr[0]), &(dst_addr[0]), &tcp_src_port);

  if (err == NO_PACKET_PARSE_ERROR) {
    display_str[1024] = '\0';
    err = ja3(ptr_tls, tls_len_max, display_str, 1024);
    if (err == NO_PACKET_PARSE_ERROR) {
      inet_ntop(af, &(src_addr[0]), src_addr_str, sizeof(src_addr_str));
      inet_ntop(af, &(dst_addr[0]), dst_addr_str, sizeof(dst_addr_str));

      md5_hash_str[32] = '\0';
      if (!md5_do(display_str, md5_hash_str)) {
	strcpy(md5_hash_str, "(md5 digest failed)");
      }

      printf("  Timestamp: %s\n", get_ts_str(pkt));
      printf("     Source: %s\n", src_addr_str);
      printf("Destination: %s\n", dst_addr_str);
      printf(" TCP source: %u\n", ntohs(tcp_src_port));
      printf(" JA3 string: %s\n", display_str);
      printf("   JA3 hash: %s\n", md5_hash_str);
      printf("\n");
    }
  }

  /* Update the errored_packets field in the context for this packet */
    
  err_pkt = &(pak_ctxt->errored_packets[err]);
  err_pkt->count++;
  if (err_pkt->count <= MAX_PACKET_ERRORS_STORED) {
    err_pkt->err_packet_tvs[err_pkt->count - 1].tv_sec = pkt->ts.tv_sec;
    err_pkt->err_packet_tvs[err_pkt->count - 1].tv_usec = pkt->ts.tv_usec;
  }
}

static void report_pcaplib_error (pcap_t *pcap, char const *addl) {
  char errbuf[PCAP_ERRBUF_SIZE + 1];
  char *pcap_err = pcap_geterr(pcap);
  if (pcap_err) {
    strncpy(errbuf, pcap_err, PCAP_ERRBUF_SIZE);
    errbuf[PCAP_ERRBUF_SIZE] = '\0';
    fprintf(stderr, "%s: %s\n", addl, errbuf);
  } else {
    fprintf(stderr, "%s: reason not known\n", addl);
  }
}

static void report_packet_analysis_result (pcap_packet_context_t *pak_ctxt) {
  struct errored_packet_t_ *err_pkt;
  packet_parse_error_t err_type;
  unsigned i;
  
  for (err_type = NO_PACKET_PARSE_ERROR; err_type < PACKET_PARSE_ERROR_MAX;
       err_type++) {
    
    err_pkt = &(pak_ctxt->errored_packets[err_type]);
    if (err_pkt->count == 0) {
      continue;
    }
    
    switch (err_type) {
      case NO_PACKET_PARSE_ERROR:
	printf("%s: %u packets\n", "                (no error)", err_pkt->count);
	break;
      case WOULD_EXCEED_BOUNDS:
	printf("%s: %u packets\n", "           Bounds exceeded", err_pkt->count);
	break;
      case UNKNOWN_ETHERTYPE:
	printf("%s: %u packets\n", "         Unknown ethertype", err_pkt->count);
	break;
	
      case UNSUPPORTED_DATALINK_LAYER:
	printf("%s: %u packets\n", "Unsupported datalink layer", err_pkt->count);
	break;
	
      case UNEXPECTED_FORMAT:
	printf("%s: %u packets\n", "         Unexpected format", err_pkt->count);
	break;

      case NOT_TLS_CLIENT_HELLO:
	printf("%s: %u packets\n", "   TLS but not interesting", err_pkt->count);
	break;

      case TLS_RECORD_BEYOND_PACKET:
	printf("%s: %u packets\n", "  TLS record out of bounds", err_pkt->count);
	break;

      default:
	fprintf(stderr, "Unexpected error type (%d)\n", err_type);
	break;
    }

    /* Print the timestamps of the errored packets. We store a max of 3 */
    for (i = 0; i < minof(MAX_PACKET_ERRORS_STORED, err_pkt->count); i++) {
      printf("                                       %lu.%lu\n",
	     err_pkt->err_packet_tvs[i].tv_sec,
	     err_pkt->err_packet_tvs[i].tv_usec);
    }
  }
}
 
int process_pcap_file (char const *pcap_file_name) {
  struct bpf_program tls_filter;
  pcap_packet_context_t pak_ctxt = {0};
  char errbuf[PCAP_ERRBUF_SIZE + 1];
  pcap_t *pcap;

  
  pcap = pcap_open_offline(pcap_file_name, errbuf);
  if (!pcap) {
    errbuf[PCAP_ERRBUF_SIZE] = '\0';
    fprintf(stderr, "Failed to open PCAP file \"%s\": %s\n", pcap_file_name,
	    errbuf);
    return -1;
  }

  /*
   * Get the datalink layer. We handle only a few types.
   */
  pak_ctxt.datalink = pcap_datalink(pcap);
  if (pak_ctxt.datalink == PCAP_ERROR_NOT_ACTIVATED) {
    fprintf(stderr, "Unable to obtain datalink layer info for this PCAP\n");
    pcap_close(pcap);
    return -1;
  }

  if ((pak_ctxt.datalink != DLT_EN10MB) &&
      (pak_ctxt.datalink != DLT_LINUX_SLL) &&
      (pak_ctxt.datalink != DLT_RAW)) {
    fprintf(stderr, "This program cannot (yet) handle datalink type %d\n",
	    pak_ctxt.datalink);
    pcap_close(pcap);
    return -1;
  }

  memset(&tls_filter, 0, sizeof(tls_filter));
  if (0 != pcap_compile(pcap, &tls_filter, "tcp dst port 443", 0,
			PCAP_NETMASK_UNKNOWN)) {
    report_pcaplib_error(pcap, "Failed to compile filter");
    pcap_close(pcap);
    return -1;
  }

  if (0 != pcap_setfilter(pcap, &tls_filter)) {
    report_pcaplib_error(pcap, "Failed to set filter");
    pcap_freecode(&tls_filter);
    pcap_close(pcap);
    return -1;
  }
  pcap_freecode(&tls_filter);

  if (0 != pcap_loop(pcap, 0, tcp_dport_443_handler, (uint8_t *) &pak_ctxt)) {
    report_pcaplib_error(pcap, "Packet processing aborted");
    pcap_close(pcap);
    return -1;
  }
  
  pcap_close(pcap);
  
  /* Analyze the pcap_packet_context_t */
  printf("%u packets analyzed\n", pak_ctxt.packet_ord);
  report_packet_analysis_result(&pak_ctxt);
  
  return 0;
}
