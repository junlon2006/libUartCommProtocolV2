/**************************************************************************
 * Copyright (C) 2017-2017  Junlon2006
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 **************************************************************************
 *
 * Description : uni_communication.c
 * Author      : junlon2006@163.com
 * Date        : 2020.04.21
 *
 **************************************************************************/
#include "uni_communication.h"

#define DEFAULT_PROTOCOL_BUF_SIZE     (sizeof(struct header))
#define PROTOCOL_BUF_GC_TRIGGER_SIZE  (1024 + sizeof(struct header))
#define PROTOCOL_BUF_SUPPORT_MAX_SIZE (8192)

//TODO need refactor, calculate by baud rate
#define WAIT_ACK_TIMEOUT_MSEC         (200)
#define TRY_RESEND_TIMES              (5)
#define NULL                          ((void *)0)
#define CHECK_NOT_NULL(ptr)           (ptr != NULL)

/*-----------------------------------------------------------------*/
/*           layout of uart communication app protocol             */
/*-----------------------------------------------------------------*/
/*--6byte-|-1byte-|-1byte-|-2byte-|-2byte-|-2byte-|-2byte-|-N byte-*/
/*"uArTcP"|  seq  |  ctrl |  cmd  | crc16 |  len  |cs(len)|payload */
/*-----------------------------------------------------------------*/

/*---------------------------ack frame-----------------------------*/
/*"uArTcP"|  seq  |  0x0  |  0x0  | crc16 |  0x0  |  0x0  |  NULL  */
/*-----------------------------------------------------------------*/

/*------------------------------------*/
/*--------------control---------------*/
/*| 8 | 7 | 6 | 5 | 4 | 3  |  2  | 1 |*/
/*|RES|RES|RES|RES|RES|NACK|ACKED|ACK|*/
/*------------------------------------*/

typedef unsigned short CommChecksum;
typedef unsigned char  CommSequence;
typedef unsigned char  CommControl;
typedef void*          InterruptHandle;

typedef struct {
  int reliable; /* 1 means this packet need acked, reliable transmission, 0 udp like*/
} CommAttribute;

typedef enum {
  ACK   = 0,  /* need ack */
  ACKED = 1,  /* ack packet */
  NACK  = 2,  /* nack packet */
} Control;

typedef enum {
  LAYOUT_SYNC_IDX                 = 0,
  LAYOUT_PAYLOAD_LEN_HIGH_IDX     = 12,
  LAYOUT_PAYLOAD_LEN_LOW_IDX      = 13,
  LAYOUT_PAYLOAD_LEN_CRC_HIGH_IDX = 14,
  LAYOUT_PAYLOAD_LEN_CRC_LOW_IDX  = 15,
} CommLayoutIndex;

typedef struct header {
  unsigned char sync[6];   /* must be "uArTcP" */
  CommSequence  sequence;  /* sequence number */
  CommControl   control;   /* header ctrl */
  unsigned char cmd[2];    /* command type, such as power on, power off etc */
  unsigned char checksum[2];         /* checksum of packet, use crc16 */
  unsigned char payload_len[2];      /* the length of payload */
  unsigned char payload_len_crc16[2];/* the crc16 of payload_len */
  char          payload[0];          /* the payload */
} PACKED CommProtocolPacket;

typedef struct {
  CommWriteHandler      on_write;
  CommRecvPacketHandler on_recv_frame;
  void*                 write_sync_lock;    /* avoid uart device write concurrency */
  void*                 app_send_sync_lock; /* avoid app send concurrency, out of sequence */
  int                   acked;
  CommSequence          sequence;
  CommSequence          current_acked_seq;  /* current received sequence */
  char                  *protocol_buffer;
  InterruptHandle       interrupt_handle;
  int                   sem_hooks_registered;
} CommProtocolBusiness;

static unsigned char        g_sync[6] = {'u', 'A', 'r', 'T', 'c', 'P'};
static CommProtocolHooks    g_hooks   = {NULL};
static CommProtocolBusiness g_comm_protocol_business;

static unsigned short _byte2_big_endian_2_u16(unsigned char *buf) {
  return ((unsigned short)buf[0] << 8) + (unsigned short)buf[1];
}

static void _u16_2_byte2_big_endian(unsigned short value, unsigned char *buf) {
  buf[0] = (unsigned char)(value >> 8);
  buf[1] = (unsigned char)(value & 0xFF);
}

static void _memcpy(void *dst, void *src, unsigned int size) {
  char *d = (char *)dst;
  char *s = (char *)src;
  int i = 0;
  while (size-- > 0) {
    d[i] = s[i];
    i++;
  }
}

static void _memset(void *s, int c, unsigned int n) {
  char *p = (char *)s;
  int i = 0;
  while (n-- > 0) {
    p[i++] = c;
  }
}

void CommProtocolRegisterHooks(CommProtocolHooks *hooks) {
  if (NULL == hooks) return;

  /* dynamic memory alloc hooks */
  g_hooks.malloc_fn  = hooks->malloc_fn;
  g_hooks.free_fn    = hooks->free_fn;
  g_hooks.realloc_fn = hooks->realloc_fn;

  /* sleep hook */
  g_hooks.msleep_fn = hooks->msleep_fn;

  /* semaphore hooks */
  g_hooks.sem_alloc_fn     = hooks->sem_alloc_fn;
  g_hooks.sem_destroy_fn   = hooks->sem_destroy_fn;
  g_hooks.sem_init_fn      = hooks->sem_init_fn;
  g_hooks.sem_post_fn      = hooks->sem_post_fn;
  g_hooks.sem_wait_fn      = hooks->sem_wait_fn;
  g_hooks.sem_timedwait_fn = hooks->sem_timedwait_fn;
}

//--------------------- UTILS crc 16---------------------------
static const unsigned short crc16tab[256] = {
  0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
  0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
  0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
  0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
  0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
  0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
  0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
  0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
  0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
  0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
  0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
  0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
  0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
  0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
  0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
  0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
  0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
  0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
  0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
  0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
  0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
  0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
  0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
  0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
  0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
  0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
  0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
  0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
  0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
  0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
  0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
  0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
};

static unsigned short _crc16(const char *buf, int len) {
  int counter;
  unsigned short crc = 0;
  for (counter = 0; counter < len; counter++) {
    crc = (crc<<8) ^ crc16tab[((crc>>8) ^ *buf++) & 0x00FF];
  }

  return crc;
}
//--------------------- UTILS crc 16---------------------------

//----------------UTILS interruptable sleep--------------------
typedef struct {
  void *v;
} Interruptable;

static int _is_sem_hook_registered() {
  return (1 == g_comm_protocol_business.sem_hooks_registered);
}

static InterruptHandle InterruptCreate() {
  Interruptable *interrupter = (Interruptable *)g_hooks.malloc_fn(sizeof(Interruptable));
  if (_is_sem_hook_registered()) {
    interrupter->v = g_hooks.sem_alloc_fn();
    g_hooks.sem_init_fn(interrupter->v, 0);
  } else {
    interrupter->v = NULL;
  }
  return (InterruptHandle)interrupter;
}

static int InterruptDestroy(InterruptHandle handle) {
  Interruptable *interrupter = (Interruptable *)handle;
  if (_is_sem_hook_registered()) {
    g_hooks.sem_destroy_fn(interrupter->v);
  }
  g_hooks.free_fn(interrupter);
  return 0;
}

static int InterruptableSleep(InterruptHandle handle, int sleep_msec) {
  Interruptable *interrupter = (Interruptable *)handle;
  if (_is_sem_hook_registered()) {
    return g_hooks.sem_timedwait_fn(interrupter->v, sleep_msec);
  }

  interrupter->v = NULL;
  while (sleep_msec-- > 0) {
    g_hooks.msleep_fn(2);
    sleep_msec -= 2;
    if (interrupter->v != NULL) break;
  }
  return 0;
}

static int InterruptableBreak(InterruptHandle handle) {
  Interruptable *interrupter = (Interruptable *)handle;
  if (_is_sem_hook_registered()) {
    return g_hooks.sem_post_fn(interrupter->v);
  }

  interrupter->v = (void *)0xFF;
  return 0;
}
//----------------UTILS interruptable sleep--------------------

static void _register_write_handler(CommWriteHandler handler) {
  g_comm_protocol_business.on_write = handler;
}

static void _unregister_write_handler() {
  g_comm_protocol_business.on_write = NULL;
}

static void _set_current_acked_seq(CommSequence seq) {
  g_comm_protocol_business.current_acked_seq = seq;
}

static CommSequence _get_current_acked_seq() {
  return g_comm_protocol_business.current_acked_seq;
}

static void _sync_set(CommProtocolPacket *packet) {
  unsigned int i;
  for (i = 0; i < sizeof(g_sync); i++) {
    packet->sync[i] = g_sync[i];
  }
}

static void _sequence_set(CommProtocolPacket *packet,
                          CommSequence seq,
                          int is_ack_packet,
                          int is_nack_packet) {
  if (is_ack_packet || is_nack_packet) {
    packet->sequence = seq;
  } else {
    packet->sequence = g_comm_protocol_business.sequence++;
  }
}

static CommSequence _current_sequence_get() {
  return g_comm_protocol_business.sequence - 1;
}

static void _bit_set(CommControl *control, int index) {
  *control |= (1 << index);
}

static int _is_bit_setted(CommControl control, int index) {
  return (control >> index) & 0x1;
}

static void _set_ack(CommProtocolPacket *packet) {
  _bit_set(&packet->control, ACK);
}

static void _set_acked(CommProtocolPacket *packet) {
  _bit_set(&packet->control, ACKED);
}

static void _set_nack(CommProtocolPacket *packet) {
  _bit_set(&packet->control, NACK);
}

static int _is_ack_set(CommControl control) {
  return _is_bit_setted(control, ACK);
}

static int _is_acked_set(CommControl control) {
  return _is_bit_setted(control, ACKED);
}

static int _is_nacked_set(CommControl control) {
  return _is_bit_setted(control, NACK);
}

static void _control_set(CommProtocolPacket *packet,
                         int reliable,
                         int is_ack_packet,
                         int is_nack_packet) {
  if (reliable) {
    _set_ack(packet);
  }

  if (is_ack_packet) {
    _set_acked(packet);
  }

  if (is_nack_packet) {
    _set_nack(packet);
  }
}

static void _cmd_set(CommProtocolPacket *packet, CommCmd cmd) {
  _u16_2_byte2_big_endian(cmd, packet->cmd);
}

static void _payload_len_set(CommProtocolPacket *packet, CommPayloadLen payload_len) {
  _u16_2_byte2_big_endian(payload_len, packet->payload_len);
}

static void _payload_len_crc16_set(CommProtocolPacket *packet) {
  unsigned short checksum = _crc16((const char *)packet->payload_len, sizeof(CommPayloadLen));
  _u16_2_byte2_big_endian(checksum, packet->payload_len_crc16);
}

static CommPayloadLen _payload_len_get(CommProtocolPacket *packet) {
  return _byte2_big_endian_2_u16(packet->payload_len);
}

static void _payload_set(CommProtocolPacket *packet,
                         char *buf, CommPayloadLen len) {
  if (NULL != buf && 0 < len) {
    _memcpy(packet->payload, buf, len);
  }
}

static char* _payload_get(CommProtocolPacket *packet) {
  return ((char *)packet) + sizeof(CommProtocolPacket);
}

static CommPayloadLen _packet_len_get(CommProtocolPacket *packet) {
  return _byte2_big_endian_2_u16(packet->payload_len) + sizeof(CommProtocolPacket) ;
}

static void _checksum_calc(CommProtocolPacket *packet) {
  packet->checksum[0] = 0; /* make sure the checksum be zero before calculate */
  packet->checksum[1] = 0;
  unsigned short checksum = _crc16((const char*)packet, _packet_len_get(packet));
  _u16_2_byte2_big_endian(checksum, packet->checksum);
}

static int _checksum_valid(CommProtocolPacket *packet) {
  CommChecksum checksum = _byte2_big_endian_2_u16(packet->checksum); /* get the checksum from packet */
  _checksum_calc(packet); /* calc checksum again */
  return (checksum == _byte2_big_endian_2_u16(packet->checksum)); /* check whether checksum valid or not */
}

static void _unset_acked_sync_flag() {
  g_comm_protocol_business.acked = 0;
}

static void _set_acked_sync_flag() {
  g_comm_protocol_business.acked = 1;
}

static int _is_acked_packet(CommProtocolPacket *protocol_packet) {
  return (_byte2_big_endian_2_u16(protocol_packet->cmd) == 0 &&
          _byte2_big_endian_2_u16(protocol_packet->payload_len) == 0 &&
          _is_acked_set(protocol_packet->control));
}

static int _is_nacked_packet(CommProtocolPacket *protocol_packet) {
  return (_byte2_big_endian_2_u16(protocol_packet->cmd) == 0 &&
          _byte2_big_endian_2_u16(protocol_packet->payload_len) == 0 &&
          _is_nacked_set(protocol_packet->control));
}

static int _wait_ack(CommAttribute *attribute, CommProtocolPacket *packet) {
  /* acked process */
  if (NULL == attribute || !attribute->reliable) {
    return 0;
  }

  InterruptableSleep(g_comm_protocol_business.interrupt_handle,
                     WAIT_ACK_TIMEOUT_MSEC);

  return g_comm_protocol_business.acked ? 0 : E_UNI_COMM_PAYLOAD_ACK_TIMEOUT;
}

static CommProtocolPacket* _packet_alloc(int payload_len) {
  CommProtocolPacket *packet = (CommProtocolPacket *)g_hooks.malloc_fn(sizeof(CommProtocolPacket) +
                                                                       payload_len);
  if (packet) {
    _memset(packet, 0, sizeof(CommProtocolPacket));
  }
  return packet;
}

static void _packet_free(CommProtocolPacket *packet) {
  g_hooks.free_fn(packet);
}

#define RESENDING  (1)
static int _resend_status(CommAttribute *attribute, int *resend_times,
                          CommProtocolPacket *packet) {
  int ret = _wait_ack(attribute, packet);
  if (0 == ret) {
    return 0;
  }

  if (*resend_times > 0) {
    *resend_times = *resend_times - 1;
    return RESENDING;
  }

  return ret;
}

/**
 * RWND always 1, in 921600bps, 512 byte payload can use 80% bandwidth 90KB/s
 * easy way to make reliable transmission, can meet current requirement
 */
static int _write_uart(CommProtocolPacket *packet, CommAttribute *attribute) {
  int ret = 0;
  int resend_times = TRY_RESEND_TIMES;

  if (NULL != g_comm_protocol_business.on_write) {
    if (NULL != attribute && attribute->reliable) {
      _unset_acked_sync_flag();
    }

    do {
      if (g_comm_protocol_business.write_sync_lock) {
        g_hooks.sem_wait_fn(g_comm_protocol_business.write_sync_lock);
      }

      g_comm_protocol_business.on_write((char *)packet,
                                        (int)_packet_len_get(packet));

      if (g_comm_protocol_business.write_sync_lock) {
        g_hooks.sem_post_fn(g_comm_protocol_business.write_sync_lock);
      }

      ret = _resend_status(attribute, &resend_times, packet);
    } while (RESENDING == ret);
  }

  return ret;
}

static void _assmeble_packet(CommProtocolPacket *packet,
                             CommCmd cmd,
                             char *payload,
                             CommPayloadLen payload_len,
                             int reliable,
                             CommSequence seq,
                             int is_ack_packet,
                             int is_nack_packet) {
  _sync_set(packet);
  _sequence_set(packet, seq, is_ack_packet, is_nack_packet);
  _control_set(packet, reliable, is_ack_packet, is_nack_packet);
  _cmd_set(packet, cmd);
  _payload_set(packet, payload, payload_len);
  _payload_len_set(packet, payload_len);
  _payload_len_crc16_set(packet);
  _checksum_calc(packet);
}

static int _is_protocol_buffer_overflow(CommPayloadLen length) {
  return length >= PROTOCOL_BUF_SUPPORT_MAX_SIZE;
}

static int _assemble_and_send_frame(CommCmd cmd,
                                    char *payload,
                                    CommPayloadLen payload_len,
                                    CommAttribute *attribute,
                                    CommSequence seq,
                                    int is_ack_packet,
                                    int is_nack_packet) {
  int ret = 0;
  if (_is_protocol_buffer_overflow(sizeof(CommProtocolPacket) +
                                   payload_len)) {
    return E_UNI_COMM_PAYLOAD_TOO_LONG;
  }

  CommProtocolPacket *packet = _packet_alloc(payload_len);
  if (NULL == packet) {
    return E_UNI_COMM_ALLOC_FAILED;
  }

  _assmeble_packet(packet, cmd, payload, payload_len,
                   attribute && attribute->reliable,
                   seq, is_ack_packet, is_nack_packet);

  ret = _write_uart(packet, attribute);
  _packet_free(packet);

  return ret;
}

int CommProtocolPacketAssembleAndSend(CommCmd cmd, char *payload,
                                      CommPayloadLen payload_len,
                                      int mode) {
  int ret;
  CommAttribute attr;
  attr.reliable = (mode == 1 ? 1 : 0);

  if (g_comm_protocol_business.app_send_sync_lock) {
    g_hooks.sem_wait_fn(g_comm_protocol_business.app_send_sync_lock);
  }

  ret = _assemble_and_send_frame(cmd, payload, payload_len,
                                 &attr, 0, 0, 0);

  if (g_comm_protocol_business.app_send_sync_lock) {
    g_hooks.sem_post_fn(g_comm_protocol_business.app_send_sync_lock);
  }

  return ret;
}

static int _packet_disassemble(CommProtocolPacket *protocol_packet,
                               CommPacket *packet) {
  if (!_checksum_valid(protocol_packet)) {
    return -1;
  }

  packet->cmd         = _byte2_big_endian_2_u16(protocol_packet->cmd);
  packet->payload_len = _payload_len_get(protocol_packet);
  packet->payload     = _payload_get(protocol_packet);

  return 0;
}

static void _enlarge_protocol_buffer(char **orginal,
                                     CommPayloadLen *orginal_len) {
  CommPayloadLen new_size = *orginal_len * 2 + sizeof(struct header); /* cover header */
  *orginal                = (char *)g_hooks.realloc_fn(*orginal, new_size);
  *orginal_len            = new_size;
}

/* small heap memory stays alway, only garbage collection big bins */
static void _try_garbage_collection_protocol_buffer(char **buffer,
                                                    CommPayloadLen *length) {
  if (*length > PROTOCOL_BUF_GC_TRIGGER_SIZE) {
    g_hooks.free_fn(*buffer);
    *buffer = NULL;
    *length = DEFAULT_PROTOCOL_BUF_SIZE;
  }
}

static void _reset_protocol_buffer_status(unsigned int *index,
                                          CommPayloadLen *length,
                                          unsigned short *crc) {
  *index = 0;
  *length = 0;
  *crc = 0;
}

static void _protocol_buffer_alloc(char **buffer,
                                   CommPayloadLen *length,
                                   unsigned int index) {
  if (NULL == *buffer) {
    *buffer = (char *)g_hooks.malloc_fn(*length);
    return;
  }

  if (*length <= index) {
    _enlarge_protocol_buffer(buffer, length);
    return;
  }
}

static void _send_nack_frame(CommSequence seq) {
  _assemble_and_send_frame(0, NULL, 0, NULL, seq, 0, 1);
}

static void _send_ack_frame(CommSequence seq) {
  _assemble_and_send_frame(0, NULL, 0, NULL, seq, 1, 0);
}

static void _do_ack(CommProtocolPacket *protocol_packet) {
  if (_is_ack_set(protocol_packet->control)) {
    _send_ack_frame(protocol_packet->sequence);
  }
}

static int _is_duplicate_frame(CommProtocolPacket *protocol_packet) {
  static int last_recv_packet_seq = -1;
  int duplicate;
  duplicate = (last_recv_packet_seq == (int)protocol_packet->sequence);
  last_recv_packet_seq = protocol_packet->sequence;
  return duplicate;
}

static void _one_protocol_frame_process(char *protocol_buffer) {
  CommProtocolPacket *protocol_packet = (CommProtocolPacket *)protocol_buffer;

  /* when application not register hook, ignore all */
  if (NULL == g_comm_protocol_business.on_recv_frame) {
    return;
  }

  /* ack frame donnot notify application, ignore it now */
  if (_is_acked_packet(protocol_packet)) {
    if (protocol_packet->sequence == _current_sequence_get()) {
      _set_acked_sync_flag();
      /* one sequence can only break once */
      if (protocol_packet->sequence != _get_current_acked_seq()) {
        _set_current_acked_seq(protocol_packet->sequence);
        InterruptableBreak(g_comm_protocol_business.interrupt_handle);
      }
    }
    return;
  }

  /* nack frame. resend immediately, donnot notify application */
  if (_is_nacked_packet(protocol_packet)) {
    /* use select can cover payload_len_crc16 error case, sem sometimes not */
    if (protocol_packet->sequence == _current_sequence_get()) {
      InterruptableBreak(g_comm_protocol_business.interrupt_handle);
    }
    return;
  }

  /* disassemble protocol buffer */
  CommPacket packet;
  if (0 != _packet_disassemble(protocol_packet, &packet)) {
    _send_nack_frame(protocol_packet->sequence);
    return;
  }

  /* ack automatically when ack attribute set */
  _do_ack(protocol_packet);

  /* notify application when not ack frame nor duplicate frame */
  if (!_is_duplicate_frame(protocol_packet)) {
    g_comm_protocol_business.on_recv_frame(&packet);
  }
}

static int _is_payload_len_crc16_valid(CommPayloadLen length,
                                       CommChecksum crc) {
  unsigned char len[2];
  _u16_2_byte2_big_endian(length, len);
  return crc == _crc16((const char *)len, sizeof(CommPayloadLen));
}

static void _protocol_buffer_generate_byte_by_byte(unsigned char recv_c) {
  static unsigned int index = 0;
  static CommPayloadLen length = 0;
  static unsigned short length_crc16 = 0;
  static CommPayloadLen protocol_buffer_length = DEFAULT_PROTOCOL_BUF_SIZE;
  CommProtocolPacket *packet;

  /* protect heap use, cannot alloc large than 8K now */
  if (_is_protocol_buffer_overflow(protocol_buffer_length)) {
    /* drop remain bytes of this frame */
    if (length > 1) {
      length--;
      return;
    }

    _reset_protocol_buffer_status(&index, &length, &length_crc16);
    _try_garbage_collection_protocol_buffer(&g_comm_protocol_business.protocol_buffer,
                                            &protocol_buffer_length);
    return;
  }

  _protocol_buffer_alloc(&g_comm_protocol_business.protocol_buffer,
                         &protocol_buffer_length, index);

  /* get frame header sync byte */
  if (index < LAYOUT_SYNC_IDX + sizeof(g_sync)) {
    if (recv_c == g_sync[index]) {
      g_comm_protocol_business.protocol_buffer[index++] = recv_c;
    } else {
      _reset_protocol_buffer_status(&index, &length, &length_crc16);
    }

    return;
  }

  /* get payload length (high 8 bit) */
  if (LAYOUT_PAYLOAD_LEN_HIGH_IDX == index) {
    length = (((unsigned short)recv_c) << 8);
    goto L_HEADER;
  }

  /* get payload length (low 8 bit) */
  if (LAYOUT_PAYLOAD_LEN_LOW_IDX == index) {
    length += recv_c;
    goto L_HEADER;
  }

  /* get payload length src16 (high 8 bit) */
  if (LAYOUT_PAYLOAD_LEN_CRC_HIGH_IDX == index) {
    length_crc16 = (((unsigned short)recv_c) << 8);
    goto L_HEADER;
  }

  if (LAYOUT_PAYLOAD_LEN_CRC_LOW_IDX == index) {
    length_crc16 += recv_c;
    if (!_is_payload_len_crc16_valid(length, length_crc16)) {
      _reset_protocol_buffer_status(&index, &length, &length_crc16);
      packet = (CommProtocolPacket *)g_comm_protocol_business.protocol_buffer;
      _send_nack_frame(packet->sequence);
      return;
    }
  }

L_HEADER:
  /* set protocol header */
  if (index < sizeof(CommProtocolPacket)) {
    g_comm_protocol_business.protocol_buffer[index++] = recv_c;
    goto L_END;
  }

  /* set protocol payload */
  if (sizeof(CommProtocolPacket) <= index && 0 < length) {
    g_comm_protocol_business.protocol_buffer[index++] = recv_c;
    length--;
  }

L_END:
  /* callback protocol buffer */
  if (sizeof(CommProtocolPacket) <= index && 0 == length) {
    _one_protocol_frame_process(g_comm_protocol_business.protocol_buffer);
    _reset_protocol_buffer_status(&index, &length, &length_crc16);
    _try_garbage_collection_protocol_buffer(&g_comm_protocol_business.protocol_buffer,
                                            &protocol_buffer_length);
  }
}

void CommProtocolReceiveUartData(unsigned char *buf, int len) {
  int i;
  for (i = 0; i < len; i++) {
    _protocol_buffer_generate_byte_by_byte(buf[i]);
  }
}

static void _register_packet_receive_handler(CommRecvPacketHandler handler) {
  g_comm_protocol_business.on_recv_frame = handler;
}

static void _unregister_packet_receive_handler() {
  g_comm_protocol_business.on_recv_frame = NULL;
}

static int _check_hooks_valid() {
  if (!CHECK_NOT_NULL(g_hooks.malloc_fn))  return -1;
  if (!CHECK_NOT_NULL(g_hooks.free_fn))    return -1;
  if (!CHECK_NOT_NULL(g_hooks.realloc_fn)) return -1;
  if (!CHECK_NOT_NULL(g_hooks.msleep_fn))  return -1;
  return 0;
}

static void _check_sem_hooks_status() {
  if (CHECK_NOT_NULL(g_hooks.sem_alloc_fn) &&
      CHECK_NOT_NULL(g_hooks.sem_destroy_fn) &&
      CHECK_NOT_NULL(g_hooks.sem_init_fn) &&
      CHECK_NOT_NULL(g_hooks.sem_post_fn) &&
      CHECK_NOT_NULL(g_hooks.sem_wait_fn) &&
      CHECK_NOT_NULL(g_hooks.sem_timedwait_fn)) {
    g_comm_protocol_business.sem_hooks_registered = 1;
  }
}

static void _protocol_business_init() {
  _memset(&g_comm_protocol_business, 0, sizeof(g_comm_protocol_business));
  _check_sem_hooks_status();
  g_comm_protocol_business.interrupt_handle = InterruptCreate();
  _set_current_acked_seq(((CommSequence)-1) >> 1);

  if (!_is_sem_hook_registered()) {
    return;
  }

  g_comm_protocol_business.write_sync_lock = g_hooks.sem_alloc_fn();
  g_hooks.sem_init_fn(g_comm_protocol_business.write_sync_lock, 1);

  g_comm_protocol_business.app_send_sync_lock = g_hooks.sem_alloc_fn();
  g_hooks.sem_init_fn(g_comm_protocol_business.app_send_sync_lock, 1);
}

static void _try_free_protocol_buffer() {
  if (NULL != g_comm_protocol_business.protocol_buffer) {
    g_hooks.free_fn(g_comm_protocol_business.protocol_buffer);
    g_comm_protocol_business.protocol_buffer = NULL;
  }
}

static void _protocol_business_final() {
  if (g_comm_protocol_business.write_sync_lock) {
    g_hooks.sem_destroy_fn(g_comm_protocol_business.write_sync_lock);
  }

  if (g_comm_protocol_business.app_send_sync_lock) {
    g_hooks.sem_destroy_fn(g_comm_protocol_business.app_send_sync_lock);
  }

  _try_free_protocol_buffer();
  InterruptDestroy(g_comm_protocol_business.interrupt_handle);
  _memset(&g_comm_protocol_business, 0, sizeof(g_comm_protocol_business));
  _memset(&g_hooks, 0, sizeof(g_hooks));
}

int CommProtocolInit(CommWriteHandler write_handler,
                     CommRecvPacketHandler recv_handler) {
  if (0 != _check_hooks_valid()) return -1;
  _protocol_business_init();
  _register_write_handler(write_handler);
  _register_packet_receive_handler(recv_handler);
  return 0;
}

void CommProtocolFinal() {
  _unregister_packet_receive_handler();
  _unregister_write_handler();
  _protocol_business_final();
}
