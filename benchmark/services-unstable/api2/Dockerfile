FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache nginx

COPY package.json .
RUN npm install --production

COPY server.js .
COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 8081

CMD sh -c "node server.js & nginx -g 'daemon off;'"

