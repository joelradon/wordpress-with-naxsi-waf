
#***********************************************************
# Run Updates and install Pre-requisites
#***********************************************************
apt update -y
#apt upgrade -y
apt -y install libpcre3-dev libssl-dev unzip build-essential daemon libxml2-dev libxslt1-dev libgd-dev libgeoip-dev zlib1g-dev libpcre3

#***********************************************************
# Install Mind Max DB for Geo IP database
#***********************************************************
sudo add-apt-repository -y ppa:maxmind/ppa
apt update -y
apt install -y libmaxminddb0 libmaxminddb-dev mmdb-bin

#***********************************************************
# Download and extract NGINX and NAXSI
#***********************************************************

mkdir ~/nginx-waf
wget https://nginx.org/download/nginx-1.16.1.tar.gz -O ~/nginx-waf/nginx.tar.gz
tar xzf ~/nginx-waf/nginx.tar.gz -C ~/nginx-waf
wget https://github.com/nbs-system/naxsi/archive/master.zip -O ~/nginx-waf/waf.zip
unzip ~/nginx-waf/waf.zip -d ~/nginx-waf/


#***********************************************************
# Git Clone GEO IP2 Module for NGINX
#***********************************************************

apt install -y git
git clone https://github.com/leev/ngx_http_geoip2_module.git /etc/ngx_http_geoip2_module


#***********************************************************
# Create script to compile NGINX with NAXSI firewall
#***********************************************************

cat > ~/nginx-waf/nginx-1.16.1/install.sh <<\EOF
cd ~/nginx-waf/nginx-1.16.1/
./configure --conf-path=/etc/nginx/nginx.conf --add-module=../naxsi-master/naxsi_src/ --error-log-path=/var/log/nginx/error.log --http-client-body-temp-path=/var/lib/nginx/body --http-fastcgi-temp-path=/var/lib/nginx/fastcgi --http-log-path=/var/log/nginx/access.log --http-proxy-temp-path=/var/lib/nginx/proxy --lock-path=/var/lock/nginx.lock --pid-path=/var/run/nginx.pid --user=www-data --group=www-data --with-http_ssl_module --without-mail_pop3_module --without-mail_smtp_module --without-mail_imap_module --without-http_uwsgi_module --add-dynamic-module=/etc/ngx_http_geoip2_module --without-http_scgi_module --prefix=/usr
make
make install
EOF

#***********************************************************
# Compile NGINX and NAXSI
#***********************************************************

sh ~/nginx-waf/nginx-1.16.1/install.sh

sleep 10s


#***********************************************************
# Configure NGINX to use fastcgi
#***********************************************************

mkdir -p /var/lib/nginx/{body,fastcgi}





#***********************************************************
# Configure Firewall Rules
#***********************************************************

cp ~/nginx-waf/naxsi-master/naxsi_config/naxsi_core.rules /etc/nginx/



cat > /etc/nginx/naxsi.rules <<\EOF
SecRulesEnabled;
DeniedUrl "/RequestDenied";
## Check Naxsi rules
CheckRule "$SQL >= 8" BLOCK;
CheckRule "$RFI >= 8" BLOCK;
CheckRule "$TRAVERSAL >= 4" BLOCK;
CheckRule "$EVADE >= 4" BLOCK;
CheckRule "$XSS >= 8" BLOCK;
EOF


#***********************************************************
# Create nginx config file with NAXSI configurations included
#***********************************************************


cat > /etc/nginx/nginx.conf <<\EOF
#user  nobody;
worker_processes  1;


load_module modules/ngx_http_geoip2_module.so;

events {
    worker_connections  1024;
}


http {
    include       mime.types;
    include       /etc/nginx/naxsi_core.rules;
        include     /etc/nginx/conf.d/*.conf;
        include     /etc/nginx/sites-enabled/*;
    
    geoip2 /etc/geo_ip/GeoLite2-Country.mmdb {
        $geoip2_data_country_code source=$remote_addr country iso_code;
        $geoip2_data_country_name source=$remote_addr country names en;
    }  

    log_format  main_geo  '$remote_addr - $remote_user [$time_local] "$request" '
                          '$status $body_bytes_sent "$http_referer" '
                          '"$http_user_agent" "$http_x_forwarded_for" '
                          '$geoip2_data_country_code $geoip2_data_country_name';

    
    access_log /var/log/nginx/access.log main_geo;
   

    default_type  application/octet-stream;
    error_log /var/log/nginx/error.log;



    #access_log  logs/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    #gzip  on;

    server {
        listen       80;
        server_name  waf.cloudforums.net;
        root /;
 
        location /.well-known/acme-challenge/ {
                root /var/www;
        }

        location / {
            return 301 https://$host$request_uri;
            include /etc/nginx/naxsi.rules;
                root   html;
                index  index.html index.htm;
        }

        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }


    }


}

EOF

sleep 1s

#***********************************************************
# Create NGINX upstart script
#***********************************************************

cat > /etc/init.d/nginx <<\EOF
#! /bin/sh PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin 
 DAEMON=/usr/sbin/nginx 
 NAME=nginx 
 DESC=nginx
 
 test -x $DAEMON || exit 0 
 # Include nginx defaults if available 
 if [ -f /etc/nginx ] ; then 
         . /etc/nginx 
 fi
 
 set -e
 
 case "$1" in 
     start)
         echo -n "Starting $DESC: " 
         start-stop-daemon --start --quiet --pidfile /var/run/nginx.pid \ 
             --exec $DAEMON -- $DAEMON_OPTS 
         echo "$NAME." 
         ;; 
     stop) 
         echo -n "Stopping $DESC: " 
         start-stop-daemon --stop --quiet --pidfile /var/run/nginx.pid \ 
             --exec $DAEMON 
         echo "$NAME." 
         ;; 
     restart|force-reload) 
         echo -n "Restarting $DESC: " 
         start-stop-daemon --stop --quiet --pidfile \ 
             /var/run/nginx.pid --exec $DAEMON 
         sleep 1 start-stop-daemon --start --quiet --pidfile \ 
             /var/run/nginx.pid --exec $DAEMON -- $DAEMON_OPTS 
         echo "$NAME." 
         ;; 
     reload) 
         echo -n "Reloading $DESC configuration: " 
         start-stop-daemon --stop --signal HUP --quiet --pidfile /var/run/nginx.pid \ 
             --exec $DAEMON 
         echo "$NAME." 
         ;; 
     *) 
         N=/etc/init.d/$NAME 
         echo "Usage: $N {start|stop|restart|force-reload}" >&2 
         exit 1 
         ;; 
 esac
 
 exit 0

EOF


systemctl daemon-reload

#***********************************************************
# Create custom NGINX service file
#***********************************************************

cat > /lib/systemd/system/nginx.service <<\EOF
[Unit]
Description=A high performance web server and a reverse proxy server
Documentation=man:nginx(8)
After=syslog.target network.target remote-fs.target nss-lookup.target
[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/usr/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=true
[Install]
WantedBy=multi-user.target
EOF



#***********************************************************
# Download GeoLite Country IP DB
#***********************************************************

mkdir /etc/geo_ip
wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.mmdb.gz
gzip -d GeoLite2-Country.mmdb.gz
mv GeoLite2-Country.mmdb /etc/geo_ip/


#***********************************************************
# Enable and Start NGINX
#***********************************************************

systemctl stop apache2
systemctl daemon-reload
systemctl enable nginx
systemctl start nginx


#***********************************************************
# Use if experiencing errors
#***********************************************************

#mkdir /etc/systemd/system/nginx.service.d
#printf "[Service]\nExecStartPost=/bin/sleep 0.1\n" > /etc/systemd/system/nginx.service.d/override.conf
#systemctl daemon-reload


#***********************************************************
# Install Certbot for SSL
#***********************************************************

#sudo apt install python-certbot-nginx -y

apt-get -y update
apt-get -y install letsencrypt
yes "joelradon@hotmail.com" | yes "a" | yes "n" | letsencrypt certonly --webroot -w /var/www -d waf.cloudforums.net



#***********************************************************
# Copy Full NGINX config including SSL
#***********************************************************


#user  nobody;
worker_processes  1;


load_module modules/ngx_http_geoip2_module.so;

events {
    worker_connections  1024;
}


http {
    include       mime.types;
    include       /etc/nginx/naxsi_core.rules;
        include     /etc/nginx/conf.d/*.conf;
        include     /etc/nginx/sites-enabled/*;
    
    geoip2 /etc/geo_ip/GeoLite2-Country.mmdb {
        $geoip2_data_country_code source=$remote_addr country iso_code;
        $geoip2_data_country_name source=$remote_addr country names en;
    }  

    log_format  main_geo  '$remote_addr - $remote_user [$time_local] "$request" '
                          '$status $body_bytes_sent "$http_referer" '
                          '"$http_user_agent" "$http_x_forwarded_for" '
                          '$geoip2_data_country_code $geoip2_data_country_name';

    
    #***********************************************************
    #Uncomment to do GeoBlocking. Default is US only in settings below
    #***********************************************************
    #map $geoip2_data_country_code $allowed_country {
    #    default no;
    #    US yes;
    # }


    access_log /var/log/nginx/access.log main_geo;
   

    default_type  application/octet-stream;
    error_log /var/log/nginx/error.log;



    #access_log  logs/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    #gzip  on;

    server {
        listen       80;
        server_name  waf.cloudforums.net;
        root /;
 
        location /.well-known/acme-challenge/ {
                root /var/www;
        }

        location / {
            return 301 https://$server_name$request_uri;
            include /etc/nginx/naxsi.rules;
                root   html;
                index  index.html index.htm;
        }

        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }


    }

    server {
      listen 443 ssl;  listen [::]:443 ssl;
      server_name waf.cloudforums.net;  

      ssl on;
      ssl_certificate      /etc/letsencrypt/live/waf.cloudforums.net/fullchain.pem;
      ssl_certificate_key  /etc/letsencrypt/live/waf.cloudforums.net/privkey.pem;

      ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256';
      ssl_protocols TLSv1.2;
      ssl_prefer_server_ciphers on;
      ssl_session_cache shared:SSL:10m;

      add_header Strict-Transport-Security "max-age=63072000;";
      ssl_stapling on;
      ssl_stapling_verify on;

      client_max_body_size 0;

      location / {
        proxy_pass http://unix:/var/discourse/shared/standalone/nginx.http.sock:;
        proxy_set_header Host $http_host;
        proxy_http_version 1.1;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Real-IP $remote_addr;
       }
    }

    # HTTPS server
    #
    #server {
    #    listen       443 ssl;
    #    server_name  localhost;

    #    ssl_certificate      cert.pem;
    #    ssl_certificate_key  cert.key;

    #    ssl_session_cache    shared:SSL:1m;
    #    ssl_session_timeout  5m;

    #    ssl_ciphers  HIGH:!aNULL:!MD5;
    #    ssl_prefer_server_ciphers  on;

    #    location / {
    #        root   html;
    #        index  index.html index.htm;
    #    }
    #}

}







systemctl restart nginx
