package com.honeypot.honeypot.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.honeypot.honeypot.model.EventoContrato;
import com.honeypot.honeypot.model.LoginAttempt;
import org.springframework.stereotype.Component;

import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class EventoMapper {

    private static final String SOURCE = "honeypot";
    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_INSTANT;
    private final ObjectMapper objectMapper;

    public EventoMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public EventoContrato mapearAEvento(LoginAttempt attempt, String eventType, String severity) {
        String eventId = (attempt.getId() != null) ? "HP-" + attempt.getId() : "HP-0";

        String timestamp = (attempt.getOccurredAt() != null)
                ? ISO_FORMATTER.format(attempt.getOccurredAt())
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

    public String toJson(LoginAttempt attempt, String eventType, String severity) throws JsonProcessingException {
        return objectMapper.writeValueAsString(mapearAEvento(attempt, eventType, severity));
    }
}