This project is not suitable for production environments.

A Kerberos authentication module for Nginx, designed to be easy to use, quick to setup and deploy, and highly secure.

### Directives

**kerberos** - enable or disable Kerberos authentication  
Syntax: `kerberos on | off;`  
Default: `kerberos off;`  
Context: `http, server, location`  

**keytab** - specify the location of the keytab to use  
Syntax: `keytab /path/to/keytab/file;`  
Default: `none - you must specify a keytab`  
Context: `http, server, location`  

#### Example configurations

TODO