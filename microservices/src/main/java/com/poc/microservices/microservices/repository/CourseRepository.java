package com.poc.microservices.microservices.repository;

import com.poc.microservices.microservices.model.Course;
import org.springframework.data.repository.PagingAndSortingRepository;

public interface CourseRepository extends PagingAndSortingRepository<Course, Long> {
}
