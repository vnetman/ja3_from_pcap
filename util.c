#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

bool safe_get_bytes (uint8_t **ptr_cursor, unsigned offset, unsigned bytes_to_read,
		     uint8_t *sentinel, void *result) {
  if (((*ptr_cursor) + offset + bytes_to_read) > sentinel) {
    return false;
  }
  (*ptr_cursor) += offset;
  memcpy(result, *ptr_cursor, bytes_to_read);
  (*ptr_cursor) += bytes_to_read;
  return true;
}

void format_error_message (int err_num, char const *fmt, ...) {
  char err_buf[256 + 1];
  char msg_buf[256 + 1];
  va_list ap;

  err_buf[256] = '\0';
  msg_buf[256] = '\0';

  strerror_r(err_num, err_buf, 256);
  
  va_start(ap, fmt);
  vsnprintf(msg_buf, 256, fmt, ap);
  va_end(ap);

  fprintf(stderr, "%s: %s\n", msg_buf, err_buf);
}
