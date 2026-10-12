package com.honeypot.honeypot.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.honeypot.honeypot.model.EventoContrato;
import com.honeypot.honeypot.model.LoginAttempt;
import org.springframework.stereotype.Component;

import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@Component
public class EventoMapper {

    private static final String DEFAULT_SOURCE = "honeypot-login-03";
    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_INSTANT;
    private final ObjectMapper objectMapper;

    public EventoMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Mapea un LoginAttempt al formato formal del contrato de eventos.
     */
    public EventoContrato mapearAEvento(LoginAttempt attempt, String eventType, String severity, String fixedEventId) {
        String eventId = (fixedEventId != null) ? fixedEventId : UUID.randomUUID().toString();

        String timestamp = (attempt.getOccurredAt() != null)
                ? ISO_FORMATTER.format(attempt.getOccurredAt())
                : "";
        String user = attempt.getUsername() != null ? attempt.getUsername() : "";
        String pass = attempt.getCredentialAttempt() != null ? attempt.getCredentialAttempt() : "";
        String ruta = attempt.getRequestPath() != null ? attempt.getRequestPath() : "/login";
        String navegador = attempt.getUserAgent() != null ? attempt.getUserAgent() : "";

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("username", user);
        details.put("password", pass);
        details.put("ruta", ruta);
        details.put("navegador", navegador);

        return new EventoContrato(
                eventId,
                timestamp,
                DEFAULT_SOURCE,
                attempt.getSourceIp(),
                attempt.getServiceAttacked(),
                severity,
                eventType,
                details
        );
    }

    public EventoContrato mapearAEvento(LoginAttempt attempt, String eventType, String severity) {
        return mapearAEvento(attempt, eventType, severity, null);
    }

    public String toJson(LoginAttempt attempt, String eventType, String severity) throws JsonProcessingException {
        return objectMapper.writeValueAsString(mapearAEvento(attempt, eventType, severity));
    }
}
