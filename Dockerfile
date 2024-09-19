FROM node:14-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install

COPY . .

EXPOSE 53/udp 3000

CMD ["node", "index.js"]