FROM ghcr.io/graalvm/graalvm-community:21 AS build

USER root

RUN microdnf install -y ca-certificates bind-utils

WORKDIR /code

COPY . .

RUN chmod +x ./gradlew

RUN ./gradlew nativeCompile -x test --no-daemon && \
    find /code/build -name "gateway" -type f 2>/dev/null || \
    find /code/build/native -type f -executable 2>/dev/null || \
    ls -la /code/build/native/nativeCompile/ 2>/dev/null || \
    echo "Arquivos gerados:" && find /code/build -type f 2>/dev/null | head -20

FROM debian:12.4-slim

WORKDIR /work/

COPY --from=build /code/build/native/nativeCompile/gateway /work/gateway

RUN chmod +x /work/gateway && chmod 775 /work

EXPOSE 8080

CMD ["./gateway", "-Xmx170M", "-Xms50M", "-Xss156k"]