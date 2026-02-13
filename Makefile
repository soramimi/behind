
all:
	mkdir -p build
	cd build && qmake ../qmake/behind.pro && make

clean:
	rm -fr _bin
	rm -fr qmake/build

install: stop
	mkdir -p /var/lib/behind
	mkdir -p /etc/behind
	mkdir -p /var/log/behind
	cp _bin/behind /usr/local/bin/
	cp -a testcase /var/lib/behind/
	cp scripts/behind.conf /etc/behind/behind.conf.example
	cp scripts/behind.service /etc/systemd/system/
	systemctl daemon-reload

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

log:
	tail -f /var/log/behind/behind.log

q1:
	dig @127.0.0.1 -p 5301 www.google.com

q2:
	dig @127.0.0.1 -p 5301 doubleclick.net

q3:
	dig @127.0.0.1 -p 5301 www.amazon.co.jp

q4:
	dig @127.0.0.1 -p 5301 www.google.com +tcp

q5:
	dig @127.0.0.1 -p 5301 www.google.com HTTPS

q6:
	dig @127.0.0.1 -p 5301 amazon.com TXT

