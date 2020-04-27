# libUartCommProtocolV2
```
1、模块的用途：串口应用层协议栈，实现类TCP协议可靠传输：保证CommProtocolPacketAssembleAndSend发送的数据【必达、有序、不重复】，也支持类似UDP传输  
2、平台适用性：该模块适用于一切平台，本身不依赖任何和系统相关的头文件及系统函数  
3、可移植性：  通过CommProtocolRegisterHooks注册，实现向各平台porting  
4、调用流程：  
4.1、通过CommProtocolRegisterHooks注册协议栈需要的功能函数，主要包含三类：动态内存分配相关函数 （必备）  
                                                                  信号量相关函数      （非必备，建议注册，可提升性能）  
                                                                  睡眠函数           （必备）  
4.2、通过CommProtocolInit初始化协议栈  
4.3、通过CommProtocolReceiveUartData接收串口收到的数据，进行协议栈解析  
4.4、通过CommProtocolPacketAssembleAndSend发送数据  
4.5、通过CommProtocolFinal注销模块，该接口理论上不应该调到  
```
