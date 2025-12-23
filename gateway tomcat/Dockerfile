FROM amazoncorretto:21 AS build

WORKDIR /build

COPY gradlew .
COPY gradle gradle
COPY build.gradle .
COPY settings.gradle .
COPY src src

RUN chmod +x ./gradlew
RUN ./gradlew build -x test --no-daemon

FROM amazoncorretto:21

WORKDIR /app

COPY --from=build /build/build/libs/*.jar app.jar

EXPOSE 8083

ENTRYPOINT ["java", "-jar", "app.jar"]
