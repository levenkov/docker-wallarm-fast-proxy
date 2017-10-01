FROM wallarm/node

COPY bin/ /usr/local/bin/
COPY wallarm/ /etc/wallarm/
COPY nginx/vhost /etc/nginx-wallarm/sites-enabled/default
COPY nginx/proxy_params /etc/nginx-wallarm/
COPY nginx/logs.conf /etc/nginx-wallarm/conf.d/
COPY supervisord.conf /etc/supervisor/
