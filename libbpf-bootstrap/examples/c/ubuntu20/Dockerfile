FROM ubuntu:20.04	
ARG DEBIAN_FRONTEND=noninteractive	

# 接下来使用sed -i进行文本的全局字符串替换来做换源操作
RUN \
 sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.163.com/g" /etc/apt/sources.list && \
 sed -i "s/http:\/\/security.ubuntu.com/http:\/\/mirrors.163.com/g" /etc/apt/sources.list && \
 apt-get update && \
 apt-get -y dist-upgrade && \
 apt-get install -y lib32z1 ssh cpio
RUN useradd -m ctf

CMD ["/bin/sh"]	

EXPOSE 9999				
