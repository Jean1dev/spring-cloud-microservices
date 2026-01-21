package com.example.gateway.performance

import io.gatling.core.Predef._
import io.gatling.http.Predef._

import scala.concurrent.duration._

class HeavyLoadTest extends Simulation {

  val httpProtocol = http
    .baseUrl("http://localhost:8083")
    .acceptHeader("application/json")
    .contentTypeHeader("application/json")
    .userAgentHeader("Gatling Heavy Load Test")

  val heavyLoadScenario = scenario("Heavy Load Test")
    .exec(
      http("Concurrent User Requests")
        .get("/user-service/users")
        .check(status.in(200, 503))
    )
    .pause(100.milliseconds)
    .exec(
      http("Concurrent Product Requests")
        .get("/product-service/products")
        .check(status.in(200, 503))
    )
    .pause(100.milliseconds)
    .exec(
      http("Concurrent Order Requests")
        .get("/order-service/orders")
        .check(status.in(200, 503))
    )
    .pause(100.milliseconds)

  val circuitBreakerScenario = scenario("Circuit Breaker Test")
    .exec(
      http("Trigger Circuit Breaker - User Service")
        .get("/user-service/users")
        .check(status.in(200, 503))
    )
    .pause(50.milliseconds)
    .repeat(10) {
      exec(
        http("Repeated Requests to Trigger CB")
          .get("/user-service/users")
          .check(status.in(200, 503))
      ).pause(10.milliseconds)
    }

  setUp(
    heavyLoadScenario.inject(
      nothingFor(5.seconds),
      rampUsers(100).during(60.seconds),
      constantUsersPerSec(50).during(120.seconds),
      rampUsersPerSec(20).to(100).during(60.seconds)
    ),
    circuitBreakerScenario.inject(
      nothingFor(10.seconds),
      atOnceUsers(20),
      rampUsers(30).during(30.seconds)
    )
  ).protocols(httpProtocol)
   .assertions(
     global.responseTime.max.lt(10000),
     global.responseTime.mean.lt(3000),
     global.successfulRequests.percent.gt(85),
     forAll.failedRequests.percent.lt(15)
   )
}
