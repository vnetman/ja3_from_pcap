#include <stdbool.h>
#include <string.h>
#include <openssl/evp.h>

static const EVP_MD *md5_impl;
static EVP_MD_CTX *md5_ctxt;

bool md5_init (void) {
  int digest_len;
  
  md5_impl = EVP_md5();

  /* Just run a basic sanity test on the digest length */
  digest_len = EVP_MD_size(md5_impl);
  if (digest_len != 16) {
    fprintf(stderr, "MD5 digest length %d is unexpected, expecting 16\n",
	    digest_len);
    return false;
  }

  md5_ctxt = EVP_MD_CTX_new();
  EVP_MD_CTX_init(md5_ctxt);

  return true;
}

void md5_shut (void) {
  EVP_MD_CTX_free(md5_ctxt);
}

bool md5_do (char const *in_string, char *dst) {
  uint8_t digest[16];
  char *cursor;
  unsigned i;

  if (!EVP_DigestInit_ex2(md5_ctxt, md5_impl, 0)) {
    fprintf(stderr, "MD5 digest initialization failed\n");
    return false;
  }
  
  if (!EVP_DigestUpdate(md5_ctxt, in_string, strlen(in_string))) {
    fprintf(stderr, "MD5 digest update failed\n");
    return false;
  }
  
  if (!EVP_DigestFinal_ex(md5_ctxt, digest, 0)) {
    printf("Message digest finalization failed.\n");
    return false;
  }

  cursor = &(dst[0]);
  for (i = 0; i < 16; i++) {
    sprintf(cursor, "%02x", digest[i]);
    cursor += 2;
  }
  *cursor = '\0';

  return true;
}
