/**************************************************************************
 * Copyright (C) 2020-2020  Junlon2006
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

/**
 * 协议栈解析输出结构体
 */
typedef struct {
  CommCmd        cmd;         /**< 消息类型，全局唯一，请使用[1, 10000]闭区间的值，其他值不可用 */
  CommPayloadLen payload_len; /**< 消息参数长度 */
  char*          payload;     /**< 消息体 */
} PACKED CommPacket;

typedef enum {
  E_UNI_COMM_ALLOC_FAILED = -10001,
  E_UNI_COMM_BUFFER_PTR_NULL,
  E_UNI_COMM_PAYLOAD_TOO_LONG,
  E_UNI_COMM_PAYLOAD_ACK_TIMEOUT,
} CommProtocolErrorCode;

/**
 * 协议栈可移植函数钩子指针集合结构体，通过注册APIs实现平台移植
 */
typedef struct {
  /* 动态内存分配相关的函数 */
  void* (*malloc_fn)(unsigned long size);             /**< malloc hook */
  void  (*free_fn)(void *ptr);                        /**< free hook */
  void* (*realloc_fn)(void *ptr, unsigned long size); /**< realloc hook */

  /* 信号量相关的函数 */
  void* (*sem_alloc_fn)(void);                         /**< 分配信号量句柄hook */
  void  (*sem_destroy_fn)(void *sem);                  /**< 回收信号量句柄hook */
  int   (*sem_init_fn)(void *sem, unsigned int value); /**< 信号量初始化hook */
  int   (*sem_post_fn)(void *sem);                     /**< 信号量释放hook */
  int   (*sem_wait_fn)(void *sem);                     /**< 信号量等待hook */
  int   (*sem_timedwait_fn)(void *sem, unsigned int timeout_msecond); /**< 信号量超时等待hook */

  /* 睡眠函数 */
  int (*msleep_fn)(unsigned int msecond); /**< 睡眠hook */
} CommProtocolHooks;

typedef void (*CommRecvPacketHandler)(CommPacket *packet);

/**
 * @brief     协议栈依赖的可移植函数，需要根据系统实际情况，进行注册
 * @param[in] hooks 注册函数指针集结构体
 * @return    void
 */
void CommProtocolRegisterHooks(CommProtocolHooks *hooks);

/**
 * @brief     协议栈初始化函数
 * @param[in] write_handler 函数指针，用于注册串口发送函数到协议栈中
 * @param[in] recv_handler  协议栈解析出数据后，封装成struct CommPacket回调给应用层
 * @return    错误码，0代表成功，-1代表失败
 */
int CommProtocolInit(CommWriteHandler write_handler, CommRecvPacketHandler recv_handler);

/**
 * @brief 协议栈反注册函数，用于释放所有资源
 * @param void
 * @return void
 */
void CommProtocolFinal(void);

/**
 * @brief                 协议栈发送消息函数，根据mode选择发送模式
 * @param[in] cmd         发送消息的类型，该类型是全局唯一的，标识一个消息类型，取值[1, 10000]闭区间，其他值不可用
 * @param[in] payload     cmd对应的消息包含的参数，如没有参数则设置为NULL
 * @param[in] payload_len cmd对应的消息参数的长度，如果没有参数设置为0
 * @param[in] mode        发送模式，1代表可靠传输类似TCP（必达，有序，不重复），0不保证可靠性类似UDP
 * @return                错误码，0代表成功，其他见CommProtocolErrorCode
 */
int CommProtocolPacketAssembleAndSend(CommCmd cmd, char *payload,
                                      CommPayloadLen payload_len,
                                      int mode);

/**
 * @brief     协议栈入口函数，即从串口接收的数据入口，通过该接口解析出struct CommPacket
 * @param[in] buf 串口接收到的数据buffer
 * @param[in] len 串口接收到的数据长度
 * @return    void
 */
void CommProtocolReceiveUartData(unsigned char *buf, int len);

#ifdef __cplusplus
}
#endif
#endif  // UNI_COMMUNICATION_H_
