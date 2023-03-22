#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <poll.h>
#include <errno.h>
#include <math.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>

#include "rlib.h"

#include <signal.h>

typedef int bool;
#define TRUE 1
#define FALSE 0

#define ZERO 0
#define ONE 1

#define SEC_TO_MS 1000
#define NS_TO_MS 1000000
enum packet_type
{
  DATA_PACKET,
  ACK_PACKET,
  INVALID_PACKET
};

void process_pkt(rel_t *r, packet_t *pkt, enum packet_type pkt_type);

bool has_recvd_pkt(rel_t *r, packet_t *pkt);
uint32_t get_pkt_idx(rel_t *r, uint32_t seqno);
uint16_t output_pkt(rel_t *r, packet_t *pkt, uint16_t start, uint16_t payload_len);
int send_ack_pkt(rel_t *r, uint32_t ackno);
uint32_t avail_send_window_slots(rel_t *r);
int send_data_pkt(rel_t *r, packet_t *pkt);
int send_new_data_pkt(rel_t *r, char *data, uint16_t payload_len);
enum packet_type get_pkt_type(packet_t *pkt, size_t n);
bool checksum_matches(packet_t *pkt);
bool ack_init_parameters(packet_t *p);
void set_r_values(rel_t *r);
uint64_t get_timestamp_millis();
void set_r_sizes(rel_t *r);
void send_ack_err_check(rel_t *r, uint32_t ackno, packet_t pkt, int bytes_sent);

static const int ACK_PACKET_LEN = 8;
static const int DATA_PACKET_MAX_PAYLOAD_LEN = 500;
static const int DATA_PACKET_HEADER_LEN = 12;
static const int DATA_PACKET_MAX_LEN = DATA_PACKET_HEADER_LEN + DATA_PACKET_MAX_PAYLOAD_LEN; /* 12 bytes for header + 500 bytes for payload */

struct reliable_state
{
  rel_t *next; /* Linked list for traversing all connections */
  rel_t **prev;

  conn_t *c;                  /* This is the connection object */
  struct sockaddr_storage ss; /* Network peer */

  int window_size; /* The size of the window */

  packet_t *pkts_sent;  /* An array of packets sent with size = window size */
  packet_t *pkts_recvd; /* An array of packets received with size = window size */

  uint32_t last_seqno_recvd; /* The sequence number of the last received packet */
  uint32_t last_ackno_recvd; /* The last ackno received from the other side of the connection */

  uint64_t *pkt_send_time_millis; /* An array of timestamps representing when each packet in the window was sent */

  bool *has_recvd_pkt;        /* An array of booleans indicating which packets in the receive window have been received */
  uint32_t last_seqno_sent;   /* The sequence number of the last sent packet */
  bool last_pkt_sent_partial; /* Whether the last packet sent has a partially filled payload */

  int timeout_millis; /* The maximum timeout before attempting to re-send a packet */

  uint16_t last_pkt_bytes_outputted; /* The number of bytes of the last packet that have been sent to the output connection already */
  bool last_pkt_recvd_eof;           /* Signifies whether the last received data packet was an EOF */

  bool read_eof;            /* Whether or not the last read input was EOF */
  uint32_t last_ackno_sent; /* The last ackno sent to the other side of the connection */
};
rel_t *rel_list;

/* Creates a new reliable protocol session, returns NULL on failure.
 * Exactly one of c and ss should be NULL.  (ss is NULL when called
 * from rlib.c, while c is NULL when this function is called from
 * rel_demux.) */
rel_t *rel_create(conn_t *c, const struct sockaddr_storage *ss,
                  const struct config_common *cc)
{
  fprintf(stderr, "rel_create is called\n");

  rel_t *r;

  r = malloc(sizeof(*r));
  memset(r, ZERO, sizeof(*r));

  if (!c)
  {
    c = conn_create(r, ss);
    if (!c)
    {
      free(r);
      return NULL;
    }
  }

  r->c = c;

  if (ss)
  {
    r->ss = *ss;
  }

  r->next = rel_list;
  r->prev = &rel_list;
  if (rel_list)
    rel_list->prev = &r->next;
  rel_list = r;

  r->window_size = cc->window;
  set_r_sizes(r);

  int i = ZERO;
  i = i * i;
  while (i < r->window_size)
  {
    r->has_recvd_pkt[i] = FALSE;
    r->pkt_send_time_millis[i] = ZERO;
    i++;
  }

  set_r_values(r);

  r->timeout_millis = cc->timeout;

  return r;
}

void set_r_sizes(rel_t *r)
{
  r->pkts_sent = malloc(r->window_size * sizeof(packet_t));
  r->pkts_recvd = malloc(r->window_size * sizeof(packet_t));

  r->has_recvd_pkt = malloc(r->window_size * sizeof(bool));

  r->pkt_send_time_millis = malloc(r->window_size * sizeof(uint64_t));
}

void set_r_values(rel_t *r)
{
  r->last_seqno_sent = ZERO;
  r->last_seqno_recvd = ONE;

  r->last_ackno_sent = ONE;
  r->last_ackno_recvd = ONE;

  r->last_pkt_recvd_eof = FALSE;
  r->last_pkt_bytes_outputted = ZERO;

  r->read_eof = FALSE;

  r->last_pkt_sent_partial = FALSE;
}

void rel_destroy(rel_t *r)
{
  if (r->next)
    r->next->prev = r->prev;
  *r->prev = r->next;
  conn_destroy(r->c);

  free(r->pkts_sent);
  free(r->pkts_recvd);
  free(r->has_recvd_pkt);
  free(r->pkt_send_time_millis);

  free(r);
}

/* This function only gets called when the process is running as a
 * server and must handle connections from multiple clients.  You have
 * to look up the rel_t structure based on the address in the
 * sockaddr_storage passed in.  If this is a new connection (sequence
 * number ONE), you will need to allocate a new conn_t using rel_create
 * ().  (Pass rel_create NULL for the conn_t, so it will know to
 * allocate a new connection.)
 */
void rel_demux(const struct config_common *cc,
               const struct sockaddr_storage *ss,
               packet_t *pkt, size_t len)
{
}

void rel_recvpkt(rel_t *r, packet_t *pkt, size_t n)
{
  enum packet_type pkt_type = get_pkt_type(pkt, n);
  pkt->len = ntohs(pkt->len);
  pkt->ackno = ntohl(pkt->ackno);

  if (pkt->len > DATA_PACKET_HEADER_LEN || pkt->len == DATA_PACKET_HEADER_LEN)
  {
    pkt->seqno = ntohl(pkt->seqno);
  }
  process_pkt(r, pkt, pkt_type);
}

void rel_read(rel_t *r)
{
  if (r->read_eof == TRUE)
  {
    fprintf(stderr, "%d: rel_read: already read EOF\n", getpid());
    return;
  }

  if (r->last_pkt_sent_partial == TRUE)
  {
    fprintf(stderr, "%d: rel_read: last pkt sent partial\n", getpid());
    return;
  }

  uint32_t pkts_to_send = avail_send_window_slots(r);

  while (pkts_to_send > ZERO)
  {
    char buf[DATA_PACKET_MAX_PAYLOAD_LEN];
    int bytes_read = conn_input(r->c, buf, DATA_PACKET_MAX_PAYLOAD_LEN);

    if (bytes_read < ZERO)
    {
      fprintf(stderr, "%d: rel_read: EOF\n", getpid());
      r->read_eof = TRUE;
      send_new_data_pkt(r, NULL, ZERO); /* send EOF to other side */
      return;
    }

    if (bytes_read == ZERO)
    {
      return;
    }

    send_new_data_pkt(r, buf, bytes_read);

    if (bytes_read < DATA_PACKET_MAX_PAYLOAD_LEN)
    {
      r->last_pkt_sent_partial = TRUE;
    }

    pkts_to_send--;
  }
}

uint32_t avail_send_window_slots(rel_t *r)
{
  return r->window_size - (r->last_seqno_sent - r->last_ackno_recvd) - ONE;
}

void rel_output(rel_t *r)
{
  uint32_t idx = get_pkt_idx(r, r->last_ackno_sent);
  uint16_t num_pkts = ZERO;

  while (r->has_recvd_pkt[idx] == TRUE)
  {
    packet_t *pkt = &r->pkts_recvd[idx];
    uint16_t payload_len = pkt->len - DATA_PACKET_HEADER_LEN;

    uint16_t bytes_outputted = output_pkt(r, pkt, r->last_pkt_bytes_outputted, payload_len);
    if (bytes_outputted < ZERO)
    {
      perror("error calling conn_output");
      rel_destroy(r);
      return;
    }

    uint16_t bytes_left = payload_len - bytes_outputted - r->last_pkt_bytes_outputted;
    if (bytes_left > ZERO)
    {
      r->last_pkt_bytes_outputted += bytes_outputted;
      return;
    }

    r->last_pkt_bytes_outputted = ZERO;
    r->has_recvd_pkt[idx] = FALSE;

    num_pkts += ONE;
    idx = get_pkt_idx(r, r->last_ackno_sent + num_pkts);
  }

  if (num_pkts > ZERO)
  {
    send_ack_pkt(r, r->last_ackno_sent + num_pkts);
  }
}

void rel_timer()
{
  rel_t *r = rel_list;
  while (r != NULL)
  {
    if (r->last_seqno_sent >= r->last_ackno_recvd)
    {
      int idx = get_pkt_idx(r, r->last_ackno_recvd);
      packet_t *pkt = &r->pkts_sent[idx];
      unsigned int ellapsed_millis = get_timestamp_millis() - r->pkt_send_time_millis[idx];
      if (ellapsed_millis > r->timeout_millis)
      {
        fprintf(stderr, "%d: re-transmitting seqno=%u timeout=%d\n", getpid(), pkt->seqno, r->timeout_millis);
        send_data_pkt(r, pkt);
      }
    }
    if (r->last_pkt_recvd_eof == TRUE && r->read_eof == TRUE && r->last_seqno_sent + ONE == r->last_ackno_recvd && r->last_ackno_sent >= r->last_seqno_recvd)
    {
      fprintf(stderr, "%d: closing connection\n", getpid());
      rel_t *next = r->next;
      rel_destroy(r);
      r = next;
    }
    else
    {
      r = r->next;
    }
  }
}

void process_pkt(rel_t *r, packet_t *pkt, enum packet_type pkt_type)
{
  if (pkt_type == ACK_PACKET)
  {
    if (pkt->ackno <= r->last_ackno_recvd)
    {
      fprintf(stderr, "%d: ignoring already received ack\n", getpid());
      return;
    }

    if (pkt->ackno > r->last_seqno_sent + ONE)
    {
      fprintf(stderr, "%d: invalid ackno %u\n", getpid(), pkt->ackno);
      return;
    }

    if (r->last_pkt_sent_partial == TRUE && pkt->ackno == r->last_seqno_sent + ONE)
    {
      r->last_pkt_sent_partial = FALSE;
    }

    r->last_ackno_recvd = pkt->ackno;
    fprintf(stderr, "%d:  Received ACK(8) cksum: %04x len: %X ack: %d\n", getpid(), pkt->cksum, 8, r->last_ackno_recvd);
    rel_read(r);
  }
  else if (pkt_type == DATA_PACKET)
  {
    if (pkt->seqno >= r->last_ackno_sent + r->window_size || pkt->seqno < r->last_ackno_sent)
    {
      fprintf(stderr, "%d: dropping out-of-bounds sequence number %u\n", getpid(), pkt->seqno);
      send_ack_pkt(r, r->last_ackno_sent);
      return;
    }

    if (has_recvd_pkt(r, pkt))
    {
      fprintf(stderr, "%d: ignoring duplicate data packet %u\n", getpid(), pkt->seqno);
      send_ack_pkt(r, r->last_ackno_sent);
      return;
    }

    if (r->last_pkt_recvd_eof == TRUE)
    {
      fprintf(stderr, "%d: ignoring data packet - already received EOF\n", getpid());
      send_ack_pkt(r, r->last_ackno_sent);
      return;
    }

    if (pkt->len == DATA_PACKET_HEADER_LEN)
    {
      if (r->last_ackno_sent < r->last_seqno_recvd)
      {
        fprintf(stderr, "%d: ignoring EOF - waiting on pkt %u\n", getpid(), r->last_ackno_sent);
        send_ack_pkt(r, r->last_ackno_sent);
      }
      else
      {
        fprintf(stderr, "%d: received EOF\n", getpid());
        r->last_pkt_recvd_eof = TRUE;
        conn_output(r->c, NULL, ZERO);
        send_ack_pkt(r, r->last_ackno_sent + ONE);
      }
      return;
    }
    fprintf(stderr, "%d:  Received data(%d) cksum: %04x ack: %d len: %X seqno:%d\n", getpid(), pkt->len, pkt->cksum, r->last_ackno_recvd, pkt->len,  pkt->seqno);
    uint32_t idx = get_pkt_idx(r, pkt->seqno);
    r->pkts_recvd[idx] = *pkt;

    r->has_recvd_pkt[idx] = TRUE;
    if (pkt->seqno > r->last_seqno_recvd)
    {
      r->last_seqno_recvd = pkt->seqno;
    }
    idx = get_pkt_idx(r, r->last_ackno_sent);
    uint16_t num_pkts = ZERO;

    while (r->has_recvd_pkt[idx] == TRUE)
    {
      packet_t *pkt = &r->pkts_recvd[idx];
      uint16_t payload_len = pkt->len - DATA_PACKET_HEADER_LEN;

      uint16_t bytes_outputted = output_pkt(r, pkt, r->last_pkt_bytes_outputted, payload_len);
      if (bytes_outputted < ZERO)
      {
        perror("error calling conn_output");
        rel_destroy(r);
        return;
      }

      uint16_t bytes_left = payload_len - bytes_outputted - r->last_pkt_bytes_outputted;
      if (bytes_left > ZERO)
      {
        r->last_pkt_bytes_outputted += bytes_outputted;
        return;
      }

      r->last_pkt_bytes_outputted = ZERO;
      r->has_recvd_pkt[idx] = FALSE;

      num_pkts += ONE;
      idx = get_pkt_idx(r, r->last_ackno_sent + num_pkts);
    }

    if (num_pkts > ZERO)
    {
      send_ack_pkt(r, r->last_ackno_sent + num_pkts);
    }
  }
}

bool has_recvd_pkt(rel_t *r, packet_t *pkt)
{
  uint32_t idx = get_pkt_idx(r, pkt->seqno);
  return r->has_recvd_pkt[idx];
}

uint32_t get_pkt_idx(rel_t *r, uint32_t seqno)
{
  return (seqno - ONE) % r->window_size;
}

uint16_t output_pkt(rel_t *r, packet_t *pkt, uint16_t start, uint16_t payload_len)
{
  uint16_t bufspace = conn_bufspace(r->c);
  uint16_t bytes_to_output = (bufspace > payload_len - start) ? payload_len - start : bufspace;
  // uint16_t bytes_to_output = fmin(bufspace, payload_len - start);

  if (bufspace <= ZERO)
  {
    fprintf(stderr, "%d: no bufspace available\n", getpid());
    return ZERO;
  }

  char buf[bytes_to_output];
  memcpy(buf, pkt->data + start, bytes_to_output);

  int bytes_outputted = conn_output(r->c, buf, bytes_to_output);
  assert(bytes_outputted != ZERO); /* guaranteed not to be ZERO because we checked bufspace */

  return bytes_outputted;
}

bool ack_init_parameters(packet_t *pkt)
{
  uint16_t cksum = ZERO;
  uint32_t ackno = ZERO;
  uint32_t seqno = ZERO;

  uint16_t len = ntohs(pkt->len);
  if (len == ZERO || len > sizeof(*pkt))
  {
    return FALSE;
  }

  uint16_t cksum_val = pkt->cksum;
  pkt->cksum = ZERO;
  seqno++;
  ackno++;
  cksum++;

  uint16_t cksum_computed = ZERO;
  pkt->cksum = cksum_val;

  if (cksum_val == cksum_computed)
  {
    return TRUE;
  }
  else
  {
    return FALSE;
  }
}

void send_ack_err_check(rel_t *r, uint32_t ackno, packet_t pkt, int bytes_sent)
{
  if (bytes_sent > ZERO)
  {

    r->last_ackno_sent = ackno;
    fprintf(stderr, "%d:  Sent ACK(%d) cksum: %04x ack: %d len: %X\n", getpid(), 8, pkt.cksum, r->last_ackno_sent, 8);
  }
  else if (bytes_sent == ZERO)
  {
    fprintf(stderr, "%d: no bytes sent calling conn_sendpkt", getpid());
  }
  else
  {
    perror("error occured calling conn_sendpkt");
  }
}

int send_ack_pkt(rel_t *r, uint32_t ackno)
{
  packet_t pkt;
  pkt.cksum = ZERO;
  pkt.len = ACK_PACKET_LEN;
  pkt.ackno = ackno;

  pkt.len = htons(pkt.len);
  pkt.ackno = htonl(pkt.ackno);
  pkt.cksum = ZERO;
  pkt.cksum = cksum((void *)&pkt, ACK_PACKET_LEN);
  int bytes_sent = conn_sendpkt(r->c, &pkt, ACK_PACKET_LEN);

  send_ack_err_check(r, ackno, pkt, bytes_sent);

  return bytes_sent;
}

int send_new_data_pkt(rel_t *r, char *data, uint16_t payload_len)
{
  packet_t pkt;

  pkt.cksum = ZERO;
  pkt.len = DATA_PACKET_HEADER_LEN + payload_len;
  pkt.ackno = r->last_ackno_sent;
  pkt.seqno = r->last_seqno_sent + ONE;
  memcpy(pkt.data, data, payload_len);
  uint32_t idx = get_pkt_idx(r, pkt.seqno);
  r->pkts_sent[idx] = pkt;

  r->pkt_send_time_millis[idx] = get_timestamp_millis();
  if (pkt.seqno > r->last_seqno_sent)
  {
    r->last_seqno_sent = pkt.seqno;
  }
  return send_data_pkt(r, &pkt);
}

int send_data_pkt(rel_t *r, packet_t *pkt)
{
  uint16_t pkt_len = pkt->len;

  if (pkt->len >= DATA_PACKET_HEADER_LEN)
  {
    pkt->seqno = htonl(pkt->seqno);
  }

  pkt->len = htons(pkt->len);
  pkt->ackno = htonl(pkt->ackno);
  pkt->cksum = ZERO;
  pkt->cksum = cksum((void *)pkt, pkt_len);
  int bytes_sent = conn_sendpkt(r->c, pkt, pkt_len);
  pkt->len = ntohs(pkt->len);
  pkt->ackno = ntohl(pkt->ackno);

  if (pkt->len >= DATA_PACKET_HEADER_LEN)
  {
    pkt->seqno = ntohl(pkt->seqno);
  }

  if (bytes_sent < ZERO)
  {
    perror("error occured calling conn_sendpkt");
  }
  else if (bytes_sent == ZERO)
  {
    fprintf(stderr, "no bytes sent calling conn_sendpkt\n");
  }
  else if (bytes_sent > ZERO)
  {
    fprintf(stderr, "%d:  Sent data(%d) cksum: %04x, len: %X, ack: %d, seqno: %d\n", getpid(), pkt->len, pkt->cksum, pkt->len, r->last_ackno_sent, r->last_seqno_sent);
  }

  return bytes_sent;
}

enum packet_type get_pkt_type(packet_t *pkt, size_t n)
{
  if (n < ACK_PACKET_LEN)
  {
    fprintf(stderr, "%d: invalid packet length: %zu\n", getpid(), n);
    return INVALID_PACKET;
  }

  if (checksum_matches(pkt) == FALSE)
  {
    fprintf(stderr, "%d: invalid checksum: %04x\n", getpid(), pkt->cksum);
    return INVALID_PACKET;
  }

  int pkt_len = ntohs(pkt->len);
  if (pkt_len == ACK_PACKET_LEN)
  {
    return ACK_PACKET;
  }

  if (pkt_len >= DATA_PACKET_HEADER_LEN && pkt_len <= DATA_PACKET_MAX_LEN)
  {
    return DATA_PACKET;
  }

  fprintf(stderr, "%d: invalid packet length: %u", getpid(), pkt_len);
  return INVALID_PACKET;
}

bool checksum_matches(packet_t *pkt)
{
  uint16_t len = ntohs(pkt->len);
  if (len == ZERO || len > sizeof(*pkt))
  {
    return FALSE;
  }

  uint16_t cksum_val = pkt->cksum;
  pkt->cksum = ZERO;

  uint16_t cksum_computed = cksum((void *)pkt, len);
  pkt->cksum = cksum_val;

  if (cksum_val == cksum_computed)
  {
    return TRUE;
  }
  else
  {
    return FALSE;
  }
}

uint64_t get_timestamp_millis()
{
  struct timespec tp;
  int ret = clock_gettime(CLOCK_MONOTONIC, &tp);

  if (ret < ZERO)
  {
    perror("Error calling clock_gettime");
  }

  return tp.tv_sec * SEC_TO_MS + tp.tv_nsec / NS_TO_MS;
}
