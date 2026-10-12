package com.honeypot.honeypot.service;

import com.honeypot.honeypot.model.EventoContrato;
import com.honeypot.honeypot.model.LoginAttempt;
import org.springframework.stereotype.Component;

import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class EventoMapper {

    private static final String SOURCE = "honeypot";
    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_INSTANT;

    public EventoContrato mapearAEvento(LoginAttempt attempt, String eventType, String severity) {
        String eventId = (attempt.getId() != null) ? "HP-" + attempt.getId() : "HP-0";

        // Truncado a segundos para que el timestamp vaya sin fracciones (ej: 2026-10-12T15:00:00Z)
        String timestamp = (attempt.getOccurredAt() != null)
                ? ISO_FORMATTER.format(attempt.getOccurredAt().truncatedTo(ChronoUnit.SECONDS))
                : "";

        String ip = (attempt.getSourceIp() != null) ? attempt.getSourceIp() : "";
        String user = (attempt.getUsername() != null) ? attempt.getUsername() : "";
        String title = "Intento de acceso en el login falso";
        String description = "Intento desde " + ip + " con el usuario " + user;

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("source_ip", attempt.getSourceIp());
        details.put("service", attempt.getServiceAttacked());
        details.put("username", attempt.getUsername());
        details.put("credential", attempt.getCredentialAttempt());
        details.put("command", attempt.getAttemptedCommand());
        details.put("ruta", attempt.getRequestPath());
        details.put("navegador", attempt.getUserAgent());

        return new EventoContrato(
                eventId,
                timestamp,
                SOURCE,
                eventType,
                severity,
                title,
                description,
                details
        );
    }
}