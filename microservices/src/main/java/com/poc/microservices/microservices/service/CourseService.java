package com.poc.microservices.microservices.service;

import com.poc.microservices.microservices.model.Course;
import com.poc.microservices.microservices.repository.CourseRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class CourseService {

    private final CourseRepository repository;

    public Iterable<Course> list(Pageable pageable) {
        log.info("listando tds cursos");
        return repository.findAll(pageable);
    }
}
