FROM alpine:3.17

LABEL author="Yongjie Zhuang"
LABEL description="homeproxy - authenticated forward HTTP proxy"

RUN apk --no-cache add tzdata

WORKDIR /usr/src/

# binary is pre-compiled
COPY homeproxy_build ./app_homeproxy

ENV TZ=Asia/Shanghai

CMD ["./app_homeproxy", "configFile=/usr/src/config/conf.yml"]
