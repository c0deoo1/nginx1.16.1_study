
default:	build

clean:
	rm -rf Makefile objs

build:
	$(MAKE) -f objs/Makefile

install:
	$(MAKE) -f objs/Makefile install

modules:
	$(MAKE) -f objs/Makefile modules

upgrade:
# 当nginx接收到USR2信号时使用execve()执行原Nginx启动命令行的第一个参数启动新实例。
# 而execve()是不会查找 PATH 环境变量的
# 所以如果启动nginx没有使用绝对路径，升级就会因为找不到命令而失败。
	/usr/local/nginx/sbin/nginx -t

	kill -USR2 `cat /usr/local/nginx/logs/nginx.pid`
	sleep 10
	test -f /usr/local/nginx/logs/nginx.pid.oldbin

	kill -QUIT `cat /usr/local/nginx/logs/nginx.pid.oldbin`
