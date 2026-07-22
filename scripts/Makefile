
main: nxdomain restart

restart:
	/etc/init.d/unbound stop
	/etc/init.d/behind restart
	/etc/init.d/unbound start

nxdomain:
	sort nxdomain.in >nxdomain.tmp
	uniq nxdomain.tmp >nxdomain.in
	rm nxdomain.tmp
	perl nxdomain.pl nxdomain.in >nxdomain.conf
