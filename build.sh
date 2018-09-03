cd /Users/dylan/Desktop/nginx-1.14.0

./configure \
--add-module=/Users/dylan/CLionProjects/nginx_kerberos \
--without-http_rewrite_module \
--prefix=. \
--conf-path=configuration \
--http-log-path=stdout \
--error-log-path=stderr \
--pid-path=process_identifier \
--lock-path=lock_file

make

cp -f objs/nginx /Users/dylan/CLionProjects/nginx_kerberos/nginx