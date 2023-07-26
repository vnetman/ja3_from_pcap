#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "ja3_from_pcap.h"

/* https://github.com/salesforce/ja3/blob/master/python/ja3.py */
static bool is_grease (uint16_t cs) {
  uint16_t grease_vals[] = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa};
  unsigned i;

  for (i = 0; i < sizeof(grease_vals) / sizeof(grease_vals[0]);
       i++) {
    if (cs == grease_vals[i]) {
      return true;
    }
  }

  /* Still here */
  return false;
}

/*
 * Try to extract the JA3 information from the TLS packet and, if successful,
 * fill up the `ja3_str` string with that information.
 */
packet_parse_error_t ja3 (uint8_t *ptr_tls, unsigned tls_len_max,
			  char *ja3_str, size_t ja3_str_len) {
  uint8_t *sentinel, *cursor, *ext_type_10, *ext_type_11, type_11_vals_len;
  uint8_t val8;
  uint32_t val32;
  uint16_t tls_version_field, handshake_tls_version, cipher_suites_len, val16;
  uint16_t ext_type, ext_type_10_len, ext_type_11_len, type_10_vals_len;
  char *ja3_str_cursor;
  int len;
  unsigned i;
  bool first_val;

  cursor = ptr_tls;
  sentinel = ptr_tls + tls_len_max;

  if (tls_len_max == 0) { /* No TLS data at all */
    return NOT_TLS_CLIENT_HELLO;
  }
  
  if (!safe_get_bytes(&cursor, 0, 1, sentinel, &val8)) {
    return WOULD_EXCEED_BOUNDS;
  }
  
  if (val8 != 0x16) { /* Handshake */
    return NOT_TLS_CLIENT_HELLO;
  }
  
  if (!safe_get_bytes(&cursor, 0, 2, sentinel, &tls_version_field)) {
    return WOULD_EXCEED_BOUNDS;
  }

  tls_version_field = ntohs(tls_version_field);
  if ((tls_version_field < 0x0300) || (tls_version_field > 0x0304)) {
    return NOT_TLS_CLIENT_HELLO;
  }

  /* Get the 2-byte TLS record length */
  if (!safe_get_bytes(&cursor, 0, 2, sentinel, &val16)) {
    return WOULD_EXCEED_BOUNDS;
  }
  val16 = ntohs(val16);

  /* If the TLS record length indicates that the record would go beyond the 
     current sentinel, that means that either the packet is malformed, or 
     it spans over multiple packets which we don't support currently.
     If the record length ends before the current sentinel, we will reel 
     in the sentinel accordingly. */
  if ((cursor + val16) > sentinel) {
    return TLS_RECORD_BEYOND_PACKET;
  }
  sentinel = cursor + val16;
  
  if (!safe_get_bytes(&cursor, 0, 1, sentinel, &val8)) {
    return WOULD_EXCEED_BOUNDS;
  }

  if (val8 != 0x1) { /* Client Hello */
    return NOT_TLS_CLIENT_HELLO;
  }

  /* Get the Handshake length, check it for sanity and adjust the sentinel
     accordingly */
  val32 = 0;
  if (!safe_get_bytes(&cursor, 0, 3, sentinel, &val32)) {
    return WOULD_EXCEED_BOUNDS;
  }
  
  /* val32 is a 24-bit value, interpret it correctly */
  val32 = ntohl(val32) >> 8;
  if ((cursor + val32) > sentinel) {
    printf("val32 is 0x%04x (%u)\n", val32, val32);
    return TLS_RECORD_BEYOND_PACKET;
  }
  sentinel = cursor + val32;

  if (!safe_get_bytes(&cursor, 0, 2, sentinel, &handshake_tls_version)) {
    return WOULD_EXCEED_BOUNDS;
  }
  
  /* Inaugurate the JA3 string with this value */
  len = snprintf(ja3_str, ja3_str_len, "%u,", (unsigned) handshake_tls_version);
  ja3_str_cursor = ja3_str + len;
  ja3_str_len -= len;

  /* 32 bytes of random data followed by a 1-byte session id length field */
  if (!safe_get_bytes(&cursor, 32, 1, sentinel, &val8)) {
    return WOULD_EXCEED_BOUNDS;
  }

  /* Jump over the session id itself, and get the 2-byte cipher suite length */
  if (!safe_get_bytes(&cursor, val8, 2, sentinel, &cipher_suites_len)) {
    return WOULD_EXCEED_BOUNDS;
  }
  cipher_suites_len = ntohs(cipher_suites_len);

  /* Iterate over and gather the cipher suites. Each cipher suite is a 2-byte
     value, so there are half as many items as cipher_suites_len */
  first_val = true;
  for (i = 0; i < (cipher_suites_len >> 1); i++) {
    if (!safe_get_bytes(&cursor, 0, 2, sentinel, &val16)) {
      return WOULD_EXCEED_BOUNDS;
    }
    val16 = ntohs(val16);
    if (is_grease(val16)) {
      continue;
    }
    len = snprintf(ja3_str_cursor, ja3_str_len, "%s%u", first_val ? "":"-", val16);
    ja3_str_cursor += len;
    ja3_str_len -= len;
    first_val = false;
  }

  /* Print the comma that terminates field 2, the cipher suites */
  len = snprintf(ja3_str_cursor, ja3_str_len, "%s", ",");
  ja3_str_cursor += len;
  ja3_str_len -= len;

  /* We must be at the Compression Methods Length field */
  if (!safe_get_bytes(&cursor, 0, 1, sentinel, &val8)) {
      return WOULD_EXCEED_BOUNDS;
  }

  /* Move forward by the number of bytes indicated by the Compression Methods
     Length values, then get the 2-byte Extensions Length */
  if (!safe_get_bytes(&cursor, val8, 2, sentinel, &val16)) {
    return WOULD_EXCEED_BOUNDS;
  }
  val16 = ntohs(val16);
  
  if ((cursor + val16) > sentinel) {
    return TLS_RECORD_BEYOND_PACKET;
  }
  sentinel = cursor + val16;

  /* Walk over every extension, get its type, append the JA3 string. Do this 
     until cursor hits sentinel. On the way, remember the positions of the 
     type 10 ("supported groups") and type 11 ("ec_point_formats") extensions,
     because we'll have to come back to them to derive the fourth and fifth
     items of the JA3 string CSV */
  ext_type_10 = ext_type_11 = 0;
  first_val = true;
  while (1) {
    /* Get the extension type */
    if (!safe_get_bytes(&cursor, 0, 2, sentinel, &ext_type)) {
      break;
    }
    ext_type = ntohs(ext_type);
    
    if (!is_grease(ext_type)) {
      len = snprintf(ja3_str_cursor, ja3_str_len, "%s%u", first_val ? "":"-",
		     ext_type);
      ja3_str_cursor += len;
      ja3_str_len -= len;
      first_val = false;
    }
    
    /* Get the extension length */
    if (!safe_get_bytes(&cursor, 0, 2, sentinel, &val16)) {
      return WOULD_EXCEED_BOUNDS;
    }
    val16 = ntohs(val16);

    /* Remember the values for the Type 10 and Type 11 extensions */
    if (ext_type == 10) {
      ext_type_10 = cursor;
      ext_type_10_len = val16;
    } else if (ext_type == 11) {
      ext_type_11 = cursor;
      ext_type_11_len = val16;
    }

    /* Move the cursor to the next extension */
    cursor += val16;
  }

  /* Print the comma that terminates field 3, the list of SSL extensions */
  len = snprintf(ja3_str_cursor, ja3_str_len, "%s", ",");
  ja3_str_cursor += len;
  ja3_str_len -= len;
  
  /* Field 4 of the JA3 string, the list of extension type-10 ("supported groups"
     a.k.a. "elliptic curves") types */
  if (ext_type_10) {
    cursor = ext_type_10;
    sentinel = cursor + ext_type_10_len;
    
    /* The cursor points to the field after the extension length field, i.e. 
       the 16-bit length of the list of supported groups */
    if (!safe_get_bytes(&cursor, 0, 2, sentinel, &type_10_vals_len)) {
      return WOULD_EXCEED_BOUNDS;
    }
    type_10_vals_len = ntohs(type_10_vals_len);

    first_val = true;
    for (i = 0; i < (type_10_vals_len >> 1); i++) {
      if (!safe_get_bytes(&cursor, 0, 2, sentinel, &val16)) {
	return WOULD_EXCEED_BOUNDS;
      }
      val16 = ntohs(val16);
      if (is_grease(val16)) {
	continue;
      }
      len = snprintf(ja3_str_cursor, ja3_str_len, "%s%u", first_val ? "":"-", val16);
      ja3_str_cursor += len;
      ja3_str_len -= len;
      first_val = false;
    }
  }
  /* Print the comma that terminates field 4 */
  len = snprintf(ja3_str_cursor, ja3_str_len, "%s", ",");
  ja3_str_cursor += len;
  ja3_str_len -= len;

  if (ext_type_11) {
    cursor = ext_type_11;
    sentinel = cursor + ext_type_11_len;
    
    /* The cursor points to the field after the extension length field, i.e. 
       the 8-bit length of the list of supported ec point formats */
    if (!safe_get_bytes(&cursor, 0, 1, sentinel, &type_11_vals_len)) {
      return WOULD_EXCEED_BOUNDS;
    }

    first_val = true;
    for (i = 0; i < type_11_vals_len; i++) {
      if (!safe_get_bytes(&cursor, 0, 1, sentinel, &val8)) {
	return WOULD_EXCEED_BOUNDS;
      }
      
      len = snprintf(ja3_str_cursor, ja3_str_len, "%s%u", first_val ? "":"-", val8);
      ja3_str_cursor += len;
      ja3_str_len -= len;
      first_val = false;
    }
  }
  
  return NO_PACKET_PARSE_ERROR;
}

/*
771,
19018-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,
2570-17513-13-10-0-45-51-35-5-43-27-18-16-65281-11-23-51914-41,
31354-29-23-24,
0
 */
