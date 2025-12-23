FROM amazoncorretto:21

WORKDIR /app

COPY build/libs/*.jar app.jar

EXPOSE 8083

ENTRYPOINT ["java", "-jar", "app.jar"]
