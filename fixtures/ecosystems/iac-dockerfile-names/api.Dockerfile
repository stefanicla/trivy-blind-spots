FROM node:latest
ADD . /app
RUN apt-get update && apt-get install -y curl
CMD ["node", "/app/server.js"]
