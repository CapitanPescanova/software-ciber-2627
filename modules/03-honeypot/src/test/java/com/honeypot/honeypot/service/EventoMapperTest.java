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
    @DisplayName("Convierte LoginAttempt y comprueba los 8 campos del contrato")
    void shouldConvertLoginAttemptToContractEventWithAll8Fields() {
        Instant ahora = Instant.parse("2026-10-12T15:00:00Z");

        LoginAttempt attempt = new LoginAttempt();
        attempt.setOccurredAt(ahora);
        attempt.setSourceIp("192.168.1.100");
        attempt.setServiceAttacked("honeypot-web");
        attempt.setUsername("admin");
        attempt.setCredentialAttempt("secreto123");
        attempt.setRequestPath("/login");
        attempt.setUserAgent("Mozilla/5.0");

        String eventType = "fuerza_bruta";
        String severity = "media";

        EventoContrato evento = mapper.mapearAEvento(attempt, eventType, severity, "uuid-test-1234");

        // Al ser record en Java moderno, se accede directamente con nombreCampo()
        assertNotNull(evento.eventId());
        assertEquals("uuid-test-1234", evento.eventId());
        assertEquals("2026-10-12T15:00:00Z", evento.timestamp());
        assertEquals("honeypot-login-03", evento.source());
        assertEquals("192.168.1.100", evento.sourceIp());
        assertEquals("honeypot-web", evento.service());
        assertEquals("media", evento.severity());
        assertEquals("fuerza_bruta", evento.eventType());

        assertNotNull(evento.details());
        assertEquals("admin", evento.details().get("username"));
        assertEquals("secreto123", evento.details().get("password"));
        assertEquals("/login", evento.details().get("ruta"));
        assertEquals("Mozilla/5.0", evento.details().get("navegador"));
    }
}
