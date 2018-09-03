cd /home/dylan/Code/nginx-1.14.0

./configure \
--add-module=/home/dylan/Code/mod_kerberos \
--without-http_rewrite_module \
--without-http_gzip_module \
--prefix=. \
--conf-path=configuration \
--http-log-path=stdout \
--error-log-path=stderr \
--pid-path=process_identifier \
--lock-path=lock_file

make

cp -f objs/nginx /home/dylan/Code/mod_kerberos/nginx