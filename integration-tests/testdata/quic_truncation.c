/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ngtcp2/ngtcp2.h>

#define REAL(name) ((__typeof__(&name))dlsym(RTLD_NEXT, #name))

static int injected, pending, quic_fd = -1;

static void record(const char *s) {
  FILE *f = fopen(getenv("NGHTTP2_TEST_RECORD"), "a");
  if (!f)
    abort();
  fprintf(f, "%s\n", s);
  fclose(f);
}

ssize_t recvmsg(int fd, struct msghdr *msg, int flags) {
  ssize_t n;
  const char *mode;

  if (fd == quic_fd && pending) {
    record("truncated-input-discarded");
    pending = 0;
  }
  n = REAL(recvmsg)(fd, msg, flags);
  if (!injected && n >= 1200 && msg->msg_iovlen == 1 &&
      (((const uint8_t *)msg->msg_iov[0].iov_base)[0] & 0xc0) == 0xc0) {
    mode = getenv("NGHTTP2_TEST_TRUNCATION");
    if (!mode)
      abort();
    if (!strcmp(mode, "payload"))
      msg->msg_flags |= MSG_TRUNC;
    else if (!strcmp(mode, "control"))
      msg->msg_flags |= MSG_CTRUNC;
    else if (!strcmp(mode, "both"))
      msg->msg_flags |= MSG_TRUNC | MSG_CTRUNC;
    else
      abort();
    injected = pending = 1;
    quic_fd = fd;
    record("truncation-injected");
  }
  return n;
}

int ngtcp2_pkt_decode_version_cid(ngtcp2_version_cid *vc, const uint8_t *data,
                                  size_t len, size_t cidlen) {
  if (pending) {
    record("truncated-input-reached-parser");
    pending = 0;
  }
  return REAL(ngtcp2_pkt_decode_version_cid)(vc, data, len, cidlen);
}
