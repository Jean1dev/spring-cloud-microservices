package com.poc.microservices.curso.repository;

import com.poc.microservices.curso.model.Course;
import org.springframework.data.repository.PagingAndSortingRepository;

public interface CourseRepository extends PagingAndSortingRepository<Course, Long> {
}
