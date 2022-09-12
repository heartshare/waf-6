# 简介

waf 是基于nginx lua研发的cc防护模块，提供网站cc攻击防卫功能，并支持不同的防御级别定制

# 特性

1. 支持WAF和CC防护，可配置开关是否开启WAF防护
2. 支持域名、网站、UserAgent等黑白名单配置
3. 支持不同的拦截规则配置
4. 支持动态定义拦截防御模块，包括cookie验证拦截，js验证拦截和验证码验证拦截

# 环境安装

## 配置系统依赖库加载

```shell
cd /root/soft
echo "/usr/local/lib" > /etc/ld.so.conf.d/usr_local_lib.conf
/sbin/ldconfig
```

## 安装lua jit

```shell
wget http://luajit.org/download/LuaJIT-2.0.4.tar.gz
tar -zxvf LuaJIT-2.0.4.tar.gz
cd LuaJIT-2.0.4
make PREFIX=/usr/local/luajit
make install PREFIX=/usr/local/luajit
export LUAJIT_LIB=/usr/local/luajit/lib
export LUAJIT_INC=/usr/local/luajit/include/luajit-2.0
ln -s /usr/local/luajit/lib/libluajit-5.1.* /lib64
```

## 安装ngx_devel_kit模块

```shell
wget https://github.com/simpl/ngx_devel_kit/archive/v0.3.0.tar.gz
tar -zxvf v0.3.0.tar.gz
```

## 安装lua-nginx-module模块

```shell
wget https://github.com/openresty/lua-nginx-module/archive/v0.10.7.tar.gz
tar -zxvf lua-nginx-module-0.10.7.tar.gz
```

## 安装lua-cjson模块

```shell
wget https://www.kyne.com.au/~mark/software/download/lua-cjson-2.1.0.tar.gz
tar -zxvf lua-cjson-2.1.0.tar.gz
cd lua-cjson-2.1.0
vim Makefile
#修改LUA_INCLUDE_DIR =   $(PREFIX)/include/为LUA_INCLUDE_DIR =   $(PREFIX)/luajit/include/luajit-2.0/
make && make install
```

## 安装gd库，省事点也可以直接执行 `yum -y install gd-devel`
### 安装zlib

```shell
wget https://nchc.dl.sourceforge.net/project/libpng/zlib/1.2.11/zlib-1.2.11.tar.gz
tar -zxvf zlib-1.2.11.tar.gz
cd zlib-1.2.11
./configure --prefix=/usr/local/zlib
make && make install
```

### 安装libpng

```shell
tar -zxvf libpng-1.6.30.tar.gz
cd libpng-1.6.30
./configure --prefix=/usr/local/png
make && make install
ln -s /usr/local/lib/libpng16.* /usr/lib64/
```

### 安装libgd

```shell
wget https://bbuseruploads.s3.amazonaws.com/libgd/gd-libgd/downloads/libgd-2.1.1.tar.gz?Signature=VvBOwqgIuuV3ylcs%2FMer1N%2BIDpM%3D&Expires=1502698157&AWSAccessKeyId=AKIAIQWXW6WLXMB5QZAQ&versionId=null&response-content-disposition=attachment%3B%20filename%3D%22libgd-2.1.1.tar.gz%22
tar -zxvf libgd-2.1.1.tar.gz
cd libgd-2.1.1
```

### 编译时注意看输出是否有开启libpng

```shell
./configure --with-png=/usr/local
make && make install
```

## 安装lua-gd模块，图形验证码需要用到

```shell
wget https://ayera.dl.sourceforge.net/project/lua-gd/lua-gd/lua-gd-2.0.33r2%20%28for%20Lua%205.1%29/lua-gd-2.0.33r2.tar.gz
tar -axvf lua-gd-2.0.33r2.tar.gz
cd lua-gd-2.0.33r2
vim Makefile
```

```
#注释第36～42行
#LUAPKG=lua5.1
#OUTFILE=gd.so
#CFLAGS=`gdlib-config --cflags` `pkg-config $(LUAPKG) --cflags` -O3 -Wall
#GDFEATURES=`gdlib-config --features |sed -e "s/GD_/-DGD_/g"`
#LFLAGS=-shared `gdlib-config --ldflags` `gdlib-config --libs` \
#    `pkg-config $(LUAPKG) --libs` -lgd
#INSTALL_PATH=`pkg-config $(LUAPKG) --variable=INSTALL_CMOD`
#第70行，gcc 编译，添加 -fPIC 参数
$(CC) -fPIC -o ...  //
#打开第48～52行注释，并做如下修改
OUTFILE=gd.so
#第49行，修改lua/luajit安装时的C库头文件所在路径
CFLAGS=-Wall `gdlib-config --cflags` -I/usr/local/include/luajit-2.0/ -O3
GDFEATURES=`gdlib-config --features |sed -e "s/GD_/-DGD_/g"`
#第51行，设置lua库版本号51
LFLAGS=-shared `gdlib-config --ldflags` `gdlib-config --libs` -llua5.1 -lgd
#第52行，设置 gd.so 的安装路径，即lua脚本会通过哪个路径读取gd.so
INSTALL_PATH=/usr/local/lib/lua/5.1
```

```shell
ln -s /usr/local/lib/libgd.so* /usr/lib64/
make && make install
```

## 安装nginx

```shell
wget http://nginx.org/download/nginx-1.10.2.tar.gz
tar -zxvf nginx-1.10.2.tar.gz
cd nginx-1.10.2
./configure --prefix=/usr/local/nginx1.10 \
--add-module=/root/soft/ngx_devel_kit-0.3.0 \
--add-module=/root/soft/lua-nginx-module-0.10.7
make && make install
ln -s /usr/local/nginx1.10 /usr/local/nginx
ln -s /usr/local/nginx/sbin/nginx /usr/bin
```

## 查看nginx依赖库

```shell
ldd nginx
```

## 测试，把下面的代码加入到nginx的配置文件nginx.conf，并重启nginx，然后访问http://192.168.23.190/lua

```shell
location /lua {
    set $test "hello, world.";
    content_by_lua '
        ngx.header.content_type = "text/plain";
        ngx.say(ngx.var.test);
    ';
}
```

## 检测lua版本

```shell
location /lua-version {
    content_by_lua '
        ngx.header.content_type = "text/plain";
        if jit then
            ngx.say(jit.version)
        else
            ngx.say(_VERSION)
         end
    ';
}
```

如果使用的是标准 Lua，访问http://192.168.23.190/lua-version应当返回响应体 Lua 5.1 ，如果是 LuaJIT 则应当返回类似 LuaJIT 2.0.2 这样的输出。
不要使用标准lua，应当使用luajit, 后者的效率比前者高多了。
也可以直接用 ldd 命令验证是否链了 libluajit-5.1 这样的 .so 文件

```shell
ldd nginx | grep lua
libluajit-5.1.so.2 => /usr/local/lib/libluajit-5.1.so.2 (0x00007f4bcfe6f000)
```

## 修改nginx.conf

配置

```shell
lua_package_path "/usr/local/nginx/waf/?.lua";
init_by_lua_file "/usr/local/nginx/waf/waf_init.lua";
access_by_lua_file "/usr/local/nginx/waf/waf_access.lua";
```

## 如何调试nginx lua

在nginx.conf开启debug日志

```shell
error_log  logs/error.log  debug;
```

lua代码测试如下：
```shell
print("hello")
```

# nginx单独location配置waf模板

```
user root;
worker_processes  1;

error_log  logs/error.log  debug;

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    lua_shared_dict limit_reqs_dict 100m;
    lua_shared_dict limit_stat_dict 20m;
    lua_shared_dict inject_stat_dict 20m;
    lua_package_path "/usr/local/nginx/waf/?.lua";
    init_by_lua_file "/usr/local/nginx/waf/initial.lua";
    sendfile        on;

    keepalive_timeout  65;

    upstream self {
        server 127.0.0.1:9090;
    }

    server
    {
        listen       9090;
        location / {
            root /usr/local/nginx/html/;
        }
    }

    server {
        listen       80;
        server_name  localhost;
        location / {
            access_by_lua_file "/usr/local/nginx/waf/access.lua";
            proxy_pass http://self;
        }

        location /lua {
            set $test "hello, world.";
            content_by_lua '
                ngx.header.content_type = "text/plain";
                ngx.say(ngx.var.test);
            ';
        }

        location = /lua-version { 
             content_by_lua '
                 ngx.header.content_type = "text/plain"; 
                 if jit then 
                     ngx.say(jit.version) 
                 else 
                     ngx.say(_VERSION) 
                 end 
            '; 
        }
    }
}
```

# nginx全局配置waf模板

```
user root;
worker_processes  1;

error_log  logs/error.log  debug;

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    lua_shared_dict limit_reqs_dict 100m;
    lua_shared_dict limit_stat_dict 20m;
    lua_shared_dict inject_stat_dict 20m;
    lua_package_path "/usr/local/nginx/waf/?.lua";
    init_by_lua_file "/usr/local/nginx/waf/initial.lua";
    access_by_lua_file "/usr/local/nginx/waf/access.lua";
    sendfile        on;

    keepalive_timeout  65;

    upstream self {
        server 127.0.0.1:9090;
    }

    server
    {
        listen       9090;
        location / {
            root /usr/local/nginx/html/;
        }
    }

    server {
        listen       80;
        server_name  localhost;
        location / {
            proxy_pass http://self;
        }

        location /lua {
            set $test "hello, world.";
            content_by_lua '
                ngx.header.content_type = "text/plain";
                ngx.say(ngx.var.test);
            ';
        }

        location = /lua-version { 
             content_by_lua '
                 ngx.header.content_type = "text/plain"; 
                 if jit then 
                     ngx.say(jit.version) 
                 else 
                     ngx.say(_VERSION) 
                 end 
            '; 
        }
    }
}
```
