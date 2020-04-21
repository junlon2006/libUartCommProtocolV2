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
 * Description : uni_communication.h
 * Author      : junlon2006@163.com
 * Date        : 2020.04.21
 *
 **************************************************************************/
#ifndef UNI_COMMUNICATION_H_
#define UNI_COMMUNICATION_H_

#ifdef __cplusplus
extern "C" {
#endif

#define PACKED              __attribute__ ((packed))

typedef unsigned short      CommCmd;
typedef unsigned short      CommPayloadLen;
typedef int                 (*CommWriteHandler)(char *buf, unsigned int len);

typedef struct {
  CommCmd        cmd; /* air condition ctrl cmd such as power_on, power_off */
  CommPayloadLen payload_len; /* parameter length of command */
  char           payload[0];  /* parameter of command */
} PACKED CommPacket;

typedef enum {
  E_UNI_COMM_ALLOC_FAILED = -10001,
  E_UNI_COMM_BUFFER_PTR_NULL,
  E_UNI_COMM_PAYLOAD_TOO_LONG,
  E_UNI_COMM_PAYLOAD_ACK_TIMEOUT,
} CommProtocolErrorCode;

typedef struct {
  /* dynamic memory alloc hooks */
  void* (*malloc_fn)(unsigned long size);             /* malloc hook */
  void  (*free_fn)(void *ptr);                        /* free hook */
  void* (*realloc_fn)(void *ptr, unsigned long size); /* realloc hook */

  /* semaphore */
  void* (*sem_alloc_fn)(void);         /* alloc sem handle */
  void  (*sem_destroy_fn)(void *sem);  /* destroy sem handle */
  int   (*sem_init_fn)(void *sem, unsigned int value); /* sem_init hook */
  int   (*sem_post_fn)(void *sem);     /* sem_post hook */
  int   (*sem_wait_fn)(void *sem);     /* sem_wait hook */
  int   (*sem_timedwait_fn)(void *sem, unsigned int timeout_msecond); /* sem_timedwait hook */

  /* sleep */
  int (*msleep_fn)(unsigned int msecond); /* sleep hook */
} CommProtocolHooks;

typedef void (*CommRecvPacketHandler)(CommPacket *packet);

/**
 * @brief communication protocol hooks register
 * @param hooks
 * @return void
 */
void CommProtocolRegisterHooks(CommProtocolHooks *hooks);

/**
 * @brief communication protocol init
 * @param write_handler the write handler, such as UartWrite int uni_uart.h
 * @param recv_handler when uart data disassemble as communication protocol frame,
          the frame will be translate to struct CommPacket,
          then the CommPacket will callback to user
 * @return 0 means success, -1 means failed
 */
int CommProtocolInit(CommWriteHandler write_handler, CommRecvPacketHandler recv_handler);

/**
 * @brief communication protocol finalize
 * @param void
 * @return void
 */
void CommProtocolFinal(void);

/**
 * @brief send one packet(communication protocol frame format)
 * @param cmd command type, should define as enum (such as power_on、power_off)
 * @param payload the payload of cmd, can set as NULL
 * @param payload_len the payload length
 * @param mode 0 udp like, 1 tcp like reliable transmission
 * @return 0 means success, other means failed
 */
int CommProtocolPacketAssembleAndSend(CommCmd cmd, char *payload,
                                      CommPayloadLen payload_len,
                                      int mode);

/**
 * @brief receive orignial uart data
 * @param buf the uart data buffer pointer
 * @param len the uart data length
 * @return void
 */
void CommProtocolReceiveUartData(unsigned char *buf, int len);

#ifdef __cplusplus
}
#endif
#endif  // UNI_COMMUNICATION_H_
