
#***********************************************************
# Run Updates and install Pre-requisites
#***********************************************************

sudo add-apt-repository -y ppa:maxmind/ppa
apt update -y
#apt upgrade -y
apt -y install libpcre3-dev libssl-dev unzip build-essential daemon libxml2-dev libxslt1-dev libgd-dev libgeoip-dev zlib1g-dev libpcre3
apt install -y libmaxminddb0 libmaxminddb-dev mmdb-bin

#***********************************************************
# Download and extract NGINX and NAXSI
#***********************************************************

mkdir ~/nginx-waf
wget https://nginx.org/download/nginx-1.16.1.tar.gz -O ~/nginx-waf/nginx.tar.gz
tar xzf ~/nginx-waf/nginx.tar.gz -C ~/nginx-waf
wget https://github.com/nbs-system/naxsi/archive/master.zip -O ~/nginx-waf/waf.zip
unzip ~/nginx-waf/waf.zip -d ~/nginx-waf/


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
        server_name  localhost;
        root /;

        location / {
            include /etc/nginx/naxsi.rules;
                root   html;
                index  index.html index.htm;
        }

        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }

        location ~ \.php$ {
            fastcgi_pass unix:/var/run/php/php7.2-fpm.sock;
            fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
            include fastcgi_params;
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
# Install PHP
#***********************************************************

sudo apt install -y php
sudo apt install -y php-pear php-fpm php-dev php-zip php-curl php-xmlrpc php-gd php-mysql php-mbstring php-xml libapache2-mod-php



#***********************************************************
# Configure PHP for NGINX
#***********************************************************


sudo sh -c "sed -i '/cgi.fix_pathinfo=1/c\cgi.fix_pathinfo=0' /etc/php/7.2/fpm/php.ini" 
sudo sh -c "echo '' >> /etc/php/7.2/fpm/php.ini"
sudo sh -c "echo '' >> /etc/php/7.2/fpm/php.ini"
sudo sh -c "echo ';***********************************************************' >> /etc/php/7.2/fpm/php.ini"
sudo sh -c "echo '; WordPress Settings ' >> /etc/php/7.2/fpm/php.ini"
sudo sh -c "echo ';***********************************************************' >> /etc/php/7.2/fpm/php.ini"
sudo sh -c "echo 'upload_max_filesize = 500M' >> /etc/php/7.2/fpm/php.ini"
sudo sh -c "echo 'post_max_size = 2000M' >> /etc/php/7.2/fpm/php.ini"
sudo sh -c "echo 'memory_limit = 2000M' >> /etc/php/7.2/fpm/php.ini"
sudo sh -c "echo 'max_execution_time = 120' >> /etc/php/7.2/fpm/php.ini"



#***********************************************************
# Configure website
#***********************************************************


mkdir /etc/nginx/sites-enabled
mkdir /etc/nginx/sites-available

sudo sh -c "cat > /etc/nginx/sites-available/mydomain.com <<\EOF
    server {
        listen 80;
	    root /var/www/html;
	    index index.php index.html index.htm;
        

        #charset koi8-r;

        #access_log  logs/host.access.log  main;

        location / {
	    include /etc/nginx/naxsi.rules;
        try_files \$uri \$uri/ /index.php?\$args;
        }

    	location ~ \.php$ {
    	fastcgi_split_path_info  ^(.+\.php)(/.+)$;
   	    fastcgi_index            index.php;
    	fastcgi_pass             unix:/var/run/php/php7.2-fpm.sock; #Ubuntu 17.10
    	include                  fastcgi_params;
    	fastcgi_param   PATH_INFO       \$fastcgi_path_info;
    	fastcgi_param   SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
	}
}
EOF
"            

sudo sh -c "ln -s /etc/nginx/sites-available/mydomain.com /etc/nginx/sites-enabled/"
sudo sh -c "rm -f /etc/nginx/sites-available/default"
sudo sh -c "rm -f /etc/nginx/sites-enabled/default"




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
# Install and Configure Maria DB 
#***********************************************************

sudo apt install -y mariadb-server 
sudo systemctl enable mariadb
sudo systemctl start mariadb





#***********************************************************
# Install Certbot for SSL
#***********************************************************

#sudo apt install python-certbot-nginx -y




#***********************************************************
# Install Wordpress
#***********************************************************

rm -rf /var/www/html/*
sudo sh -c "wget https://wordpress.org/latest.tar.gz -o /var/www/html/latest.tar.gz"
sudo sh -c "tar -zxvf latest.tar.gz -C /var/www/html/ --strip-components=1"
sudo sh -c "rm -rf /var/www/html/latest.tar.gz"
sudo sh -c "cp /var/www/html/wp-config-sample.php /var/www/html/wp-config.php"



#***********************************************************
# Set Permissions for /var/www/html
#***********************************************************

sudo chown -R www-data:www-data /var/www/html/*
sudo chmod -R 755 /var/www/html/*


#***********************************************************
# Generate and set MYSQL credentials
#***********************************************************

sudo sh -c "apt-get install -y pwgen > /dev/null 2>&1"
NEW_MYSQL_ROOT_PASSWORD=`pwgen -c -n -1 20` > /dev/null 2>&1
MYSQL_WP_PASSWORD=`pwgen -c -n -1 20` > /dev/null 2>&1
echo "MYSQL ROOT PASSWORD: ${NEW_MYSQL_ROOT_PASSWORD}" >> /root/passwords.txt
echo "MYSQL WP PASSWORD: ${MYSQL_WP_PASSWORD}" >> /root/passwords.txt
chmod 600 /root/passwords.txt

#***********************************************************
# Create MYSQL DB and USER
#***********************************************************

sudo sh -c "mysql -uroot mysql -e \"CREATE DATABASE wp\""
sudo sh -c "mysql -uroot mysql -e \"CREATE USER wp\""
sudo sh -c "mysql -uroot wp -e \"GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, ALTER ON wp.* TO 'wp'@'localhost' IDENTIFIED BY '${MYSQL_WP_PASSWORD}'\""
#sudo sh -c "mysql -uroot mysql -e \"ALTER USER 'root'@'localhost' IDENTIFIED BY '${NEW_MYSQL_ROOT_PASSWORD}'\""

#***********************************************************
# Add DB User and pw to Wordpress
#***********************************************************

sed -i 's/database_name_here/wp/' /var/www/html/wp-config.php
sed -i 's/username_here/wp/' /var/www/html/wp-config.php
sed -i "s/password_here/"${MYSQL_WP_PASSWORD}"/" /var/www/html/wp-config.php



