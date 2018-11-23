## 基于spring boot2 sso Oauth2 Client
## 启动前修改application.properties中的相关参数
### 当client和server在一台主机时，请用域名访问，否则cookies会相互覆盖，影响测试，以下配置仅供参考
* hosts文件
````hosts
127.0.0.1 client.sso.com
127.0.0.1 server.sso.com
````
* nginx配置
````nginx
server {
        server_name client.sso.com;
        listen 80;
        listen [::]:80;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header REMOTE-HOST $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;


        index index.html;

        location / {
                proxy_pass http://localhost:10480/;
        }
}

server {
        server_name server.sso.com;
        listen 80;
        listen [::]:80;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header REMOTE-HOST $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;


        index index.html;

        location / {
                proxy_pass http://localhost:10380/;
        }
}
````