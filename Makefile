all:
	apxs -lgssapi_krb5 -lapr-1 -laprutil-1 -c mod_kerberos.c
install:
	apxs -i mod_kerberos.la
clean:
	rm -f mod_kerberos.la mod_kerberos.lo mod_kerberos.o mod_kerberos.slo
	rm -rf .libs
