
all:
	mkdir -p build
	cd build && qmake ../behind.pro && make

clean:
	rm -fr _bin
	rm -fr build

install:
	cp scripts/behind.service /etc/systemd/system/

restart:
	sudo systemctl restart behind

start:
	sudo systemctl start behind

stop:
	sudo systemctl stop behind

enable:
	sudo systemctl enable behind

disable:
	sudo systemctl disable behind

q1:
	dig @127.0.0.1 -p 5300 www.google.com

q2:
	dig @127.0.0.1 -p 5300 doubleclick.net

q3:
	dig @127.0.0.1 -p 5300 www.soramimi.jp

q4:
	dig @127.0.0.1 -p 5300 www.amazon.co.jp
