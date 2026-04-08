
main: nxdomain restart

restart:
	systemctl restart behind

nxdomain:
	sort nxdomain.in >nxdomain.tmp
	uniq nxdomain.tmp >nxdomain.in
	rm nxdomain.tmp
	perl nxdomain.pl nxdomain.in >nxdomain.conf
