package com.honeypot.honeypot.repository;

import com.honeypot.honeypot.model.LoginAttempt;

import java.time.Instant;

import org.springframework.data.jpa.repository.JpaRepository;

public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, Long> {
    long countBySourceIpAndOccurredAtAfter(String sourceIp, Instant since);
}