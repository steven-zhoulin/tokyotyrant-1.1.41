# tokyotyrant-1.1.41

### 介绍
在官方 tokyotyrant-1.1.41 基础上：
* 增加对 ipv4 / ipv6 双栈支持。
* 增加对原地址的白名单支持。

### 安装教程

```shell
# 安装依赖
yum install zlib-devel bzip2-devel

# 创建组
groupadd tokyo

# 创建用户
useradd -d /home/tt -g tokyo tt

# 创建目录
su - tt
mkdir bin data etc logs support temp tools
```

安装 tokyocabinet
```shell
tar -zxvf tokyocabinet-1.4.48.tar.gz
cd tokyocabinet-1.4.48
./configure --prefix=/home/tt/support/tc
make
make install
```

安装 tokyotyrant
```shell
git clone https://gitee.com/steven-zhoulin/tokyotyrant-1.1.41.git
./configure --prefix=/home/tt/support/tt --with-tc=/home/tt/support/tc
make
make install
```

启动脚本
```shell
#!/bin/sh

export TC_HOME=${HOME}/support/tc
export TT_HOME=${HOME}/support/tt

${TT_HOME}/bin/ttserver -host 0.0.0.0 -port 11211 -thnum 8 -dmn -pid $HOME/logs/ttserver.pid -Z $HOME/etc/acl.conf\
-log $HOME/logs/ttserver.log -le -ulog $HOME/logs -ulim 128m -sid 1 \
-rts $HOME/logs/ttserver.rts $HOME/data/database.tch
```

停止脚本
```shell
#!/bin/sh

kill `cat ~/logs/ttserver.pid` && echo "shutdown success!"
```

配置白名单策略，位置：$HOME/etc/acl.conf
```shell
# 精确匹配
127.0.0.1
192.168.181.128
2408:8207:2550:4c00:4c2:6589:e4ee:60f6

# 网段匹配
192.168.0.0/16
2408:8207:2550:4c00:4c2:6589:e4ee:70f6/96
```

启动日志
```shell
-----------------------------------------------------------
ipv4 rule: 01111111 00000000 00000000 00000001  mask_len: 32
ipv4 rule: 11000000 10101000 10110101 10000000  mask_len: 32
ipv6 rule: 0010010000001000 1000001000000111 0010010101010000 0100110000000000 0000010011000010 0110010110001001 1110010011101110 0110000011110110  mask_len: 128
ipv4 rule: 11000000 10101000 00000000 00000000  mask_len: 16
ipv6 rule: 0010010000001000 1000001000000111 0010010101010000 0100110000000000 0000010011000010 0110010110001001 0000000000000000 0000000000000000  mask_len: 96
-----------------------------------------------------------
```

### 使用说明

简单验证
```shell
[tt@c7-n1 ~]$ curl -XPUT http://127.0.0.1:11211/k1 -d "v1"
Created
[tt@c7-n1 ~]$ curl -XGET http://127.0.0.1:11211/k1
v1
```