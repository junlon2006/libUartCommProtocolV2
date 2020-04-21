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
 * Description : rt_thread_demo.c
 * Author      : junlon2006@163.com
 * Date        : 2020.04.21
 *
 **************************************************************************/
#include "uni_communication.h"

#include <rtthread.h>

static int __msleep(unsigned int msecond) {
  return rt_thread_mdelay(msecond);
}

static void* __sem_alloc() {
  return rt_malloc(sizeof(struct rt_semaphore));
}

static void __sem_destroy(void *sem) {
  rt_sem_detach(sem);
  return rt_free(sem);
}

static int __sem_init(void *sem, unsigned int value) {
  struct rt_semaphore *s = (struct rt_semaphore *)sem;
  return rt_sem_init(s, "sem", value, RT_IPC_FLAG_FIFO);
}

static int __sem_post(void *sem) {
  struct rt_semaphore *s = (struct rt_semaphore *)sem;
  return rt_sem_release(s);
}

static int __sem_wait(void *sem) {
  struct rt_semaphore *s = (struct rt_semaphore *)sem;
  return rt_sem_take(s, RT_WAITING_FOREVER);
}

static int __sem_timedwait(void *sem, unsigned int msec) {
  struct rt_semaphore *s = (struct rt_semaphore *)sem;
  return rt_sem_take(s, rt_tick_from_millisecond(msec));
}

static void __hook_init(CommProtocolHooks *hooks) {
  /* 注册动态内存分配Hooks */
  hooks->malloc_fn  = rt_malloc;
  hooks->free_fn    = rt_free;
  hooks->realloc_fn = rt_realloc;

  /* 注册sleep Hook，以毫秒为单位，精度1ms */
  hooks->msleep_fn = __msleep;

  /* 注册信号量相关的Hook */
  hooks->sem_alloc_fn     = __sem_alloc;
  hooks->sem_destroy_fn   = __sem_destroy;
  hooks->sem_init_fn      = __sem_init;
  hooks->sem_post_fn      = __sem_post;
  hooks->sem_wait_fn      = __sem_wait;
  hooks->sem_timedwait_fn = __sem_timedwait;
}

#define HEART_BEAT_COMMAND  (100)
struct heartbeat_t {
  int sequence;
};

//调用串口写数据API，协议栈将通过该接口发送串口数据
static int __uart_write_api(char *buf, unsigned int len) {
  //真实的串口写数据实现
  return 0;
}

static void _do_heartbeat(char *buf, unsigned int len) {
  struct heartbeat_t *h = (struct heartbeat_t *)buf;
}

//协议栈解析接收到的串口数据
static void __recv_comm_packet(CommPacket *packet) {
  /*
     packet->cmd; //这条命令的消息号
     packet->payload; //命令带的参数信息
     packet->payload_len; //参数长度
   */
  switch (packet->cmd) {
    case HEART_BEAT_COMMAND:
      _do_heartbeat(packet->payload, packet->payload_len);
      break;
    default:
      break;
  }
}

int main(int argc, char *argv[]) {
  //step1. 注册协议栈依赖hooks
  CommProtocolHooks hooks;
  __hook_init(&hooks);
  CommProtocolRegisterHooks(&hooks);

  //step2. 协议栈初始化
  CommProtocolInit(__uart_write_api, __recv_comm_packet);

  //step3. 初始化完成后，即可以接收串口数据，如果要往串口写数据调用CommProtocolPacketAssembleAndSend();
  //假设要往对端发送hearbeat，heartbeat结构需要双方协定好
  struct heartbeat_t h;
  h.sequence = 1;
  //Tips：参数HEART_BEAT_COMMAND为heartbeat的命令号，h为heartbeat消息带的参数，sizeof(h)参数长度，1代表可靠传输类似TCP
  int ret = CommProtocolPacketAssembleAndSend(HEART_BEAT_COMMAND, (char *)&h, sizeof(h), 1);
  if (ret == 0) {
    //发送成功了
  }

  return 0;
}
