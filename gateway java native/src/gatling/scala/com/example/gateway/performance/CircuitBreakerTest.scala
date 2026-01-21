package com.example.gateway.performance

import io.gatling.core.Predef._
import io.gatling.http.Predef._

import scala.concurrent.duration._

class CircuitBreakerTest extends Simulation {

  val httpProtocol = http
    .baseUrl("http://localhost:8083")
    .acceptHeader("application/json")
    .contentTypeHeader("application/json")
    .userAgentHeader("Gatling Circuit Breaker Test")

  val circuitBreakerScenario = scenario("Circuit Breaker Resilience Test")
    .exec(
      http("User Service - Normal Load")
        .get("/user-service/users")
        .check(status.in(200, 503))
    )
    .pause(1)
    .exec(
      http("Product Service - Normal Load")
        .get("/product-service/products")
        .check(status.in(200, 503))
    )
    .pause(1)
    .exec(
      http("Order Service - Normal Load")
        .get("/order-service/orders")
        .check(status.in(200, 503))
    )
    .pause(2)
    .exec(
      http("Fallback Test - User Service")
        .get("/user-service/users")
        .check(status.in(200, 503))
    )
    .pause(1)
    .exec(
      http("Fallback Test - Product Service")
        .get("/product-service/products")
        .check(status.in(200, 503))
    )
    .pause(1)
    .exec(
      http("Fallback Test - Order Service")
        .get("/order-service/orders")
        .check(status.in(200, 503))
    )

  val stressScenario = scenario("Stress Test for Circuit Breaker")
    .repeat(50) {
      exec(
        http("High Frequency Requests")
          .get("/user-service/users")
          .check(status.in(200, 503))
      ).pause(100.milliseconds)
    }

  setUp(
    circuitBreakerScenario.inject(
      nothingFor(5.seconds),
      atOnceUsers(5),
      rampUsers(20).during(30.seconds),
      constantUsersPerSec(10).during(60.seconds)
    ),
    stressScenario.inject(
      nothingFor(10.seconds),
      atOnceUsers(15),
      rampUsers(25).during(45.seconds)
    )
  ).protocols(httpProtocol)
   .assertions(
     global.responseTime.max.lt(8000),
     global.responseTime.mean.lt(2500),
     global.successfulRequests.percent.gt(80),
     forAll.failedRequests.percent.lt(20)
   )
}
