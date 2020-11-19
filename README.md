# RK3399-Spi-flash-I2C-drivers
Android 7.1
在kernel的SPI和I2C子系统下分别注册一个驱动
在dts中添加对应节点
两个驱动实现相同的文件操作，使用统一的应用层接口
dts中两个设备节点不同时生效使得两个驱动不同时probe
附带简单的接口测试程序
