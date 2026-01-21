package com.example.gateway.performance

import io.gatling.core.Predef._
import io.gatling.http.Predef._

import scala.concurrent.duration._

class GatewayPerformanceTest extends Simulation {

  val httpProtocol = http
    .baseUrl("http://localhost:8083")
    .acceptHeader("application/json")
    .contentTypeHeader("application/json")
    .userAgentHeader("Gatling Performance Test")

  val scn = scenario("Gateway Performance Test")
    .exec(
      http("Health Check")
        .get("/actuator/health")
        .check(status.is(200))
    )
    .pause(1)
    .exec(
      http("User Service - Get Users")
        .get("/user-service/users")
        .check(status.in(200, 503))
    )
    .pause(1)
    .exec(
      http("Product Service - Get Products")
        .get("/product-service/products")
        .check(status.in(200, 503))
    )
    .pause(1)
    .exec(
      http("Order Service - Get Orders")
        .get("/order-service/orders")
        .check(status.in(200, 503))
    )
    .pause(1)
    .exec(
      http("User Service - Create User")
        .post("/user-service/users")
        .body(StringBody("""{"name": "Test User", "email": "test@example.com"}"""))
        .check(status.in(200, 201, 503))
    )
    .pause(1)
    .exec(
      http("Product Service - Create Product")
        .post("/product-service/products")
        .body(StringBody("""{"name": "Test Product", "price": 29.99, "description": "Test Description"}"""))
        .check(status.in(200, 201, 503))
    )
    .pause(1)
    .exec(
      http("Order Service - Create Order")
        .post("/order-service/orders")
        .body(StringBody("""{"userId": 1, "productId": 1, "quantity": 2}"""))
        .check(status.in(200, 201, 503))
    )

  setUp(
    scn.inject(
      nothingFor(5.seconds),
      atOnceUsers(10),
      rampUsers(50).during(30.seconds),
      constantUsersPerSec(20).during(60.seconds),
      rampUsersPerSec(10).to(30).during(30.seconds)
    )
  ).protocols(httpProtocol)
   .assertions(
     global.responseTime.max.lt(5000),
     global.responseTime.mean.lt(2000),
     global.successfulRequests.percent.gt(80)
   )
}
