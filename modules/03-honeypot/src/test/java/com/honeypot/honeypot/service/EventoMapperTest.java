package com.honeypot.honeypot.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.honeypot.honeypot.model.EventoContrato;
import com.honeypot.honeypot.model.LoginAttempt;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class EventoMapperTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final EventoMapper mapper = new EventoMapper(objectMapper);

    @Test
    @DisplayName("Convierte LoginAttempt al contrato comun SIEM con los 8 campos raiz")
    void shouldMapToSiemCommonContract() {
        Instant ahora = Instant.parse("2026-10-12T15:00:00Z");

        LoginAttempt attempt = new LoginAttempt();
        attempt.setId(42L);
        attempt.setOccurredAt(ahora);
        attempt.setSourceIp("192.168.1.100");
        attempt.setServiceAttacked("honeypot-web");
        attempt.setUsername("admin");
        attempt.setCredentialAttempt("secreto123");
        attempt.setAttemptedCommand(null);
        attempt.setRequestPath("/login");
        attempt.setUserAgent("Mozilla/5.0");

        String eventType = "fuerza_bruta";
        String severity = "medium";

        EventoContrato evento = mapper.mapearAEvento(attempt, eventType, severity);

        assertEquals("HP-42", evento.eventId());
        assertEquals("2026-10-12T15:00:00Z", evento.timestamp());
        assertEquals("honeypot", evento.source());
        assertEquals("fuerza_bruta", evento.eventType());
        assertEquals("medium", evento.severity());
        assertEquals("Intento de acceso en el login falso", evento.title());
        assertEquals("Intento desde 192.168.1.100 con el usuario admin", evento.description());

        assertNotNull(evento.details());
        assertEquals("192.168.1.100", evento.details().get("source_ip"));
        assertEquals("honeypot-web", evento.details().get("service"));
        assertEquals("admin", evento.details().get("username"));
        assertEquals("secreto123", evento.details().get("credential"));
        assertNull(evento.details().get("command"));
        assertEquals("/login", evento.details().get("ruta"));
        assertEquals("Mozilla/5.0", evento.details().get("navegador"));
    }
}