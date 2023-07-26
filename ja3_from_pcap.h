#ifndef __JA3_FROM_PCAP_H__
#define __JA3_FROM_PCAP_H__

#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>

typedef enum packet_parse_error_t_ {
  NO_PACKET_PARSE_ERROR = 0,
  WOULD_EXCEED_BOUNDS,
  UNKNOWN_ETHERTYPE,
  UNSUPPORTED_DATALINK_LAYER,
  UNEXPECTED_FORMAT,
  NOT_TLS_CLIENT_HELLO,
  TLS_RECORD_BEYOND_PACKET,
  PACKET_PARSE_ERROR_MAX
} packet_parse_error_t;

/* Context data structure sent to packet processing callback */
#define MAX_PACKET_ERRORS_STORED 3

typedef struct pcap_packet_context_t_ {
  int datalink;
  unsigned int packet_ord;
  struct errored_packet_t_ {
    unsigned count;
    struct timeval err_packet_tvs[MAX_PACKET_ERRORS_STORED];
  } errored_packets[PACKET_PARSE_ERROR_MAX];
} pcap_packet_context_t;

#define minof(a,b) ((a) < (b) ? (a) : (b))

extern bool safe_get_bytes(uint8_t **ptr_cursor, unsigned offset,
			   unsigned bytes_to_read, uint8_t *sentinel,
			   void *result);
extern packet_parse_error_t ja3(uint8_t *ptr_tls, unsigned tls_len_max,
				char *ja3_str, size_t ja3_str_len);
extern void format_error_message(int err_num, char const *fmt, ...);

extern bool md5_init(void);
extern void md5_shut(void);
extern bool md5_do(char const *in_string, char *dst);

extern int process_pcap_file(char const *pcap_file_name);

#endif
