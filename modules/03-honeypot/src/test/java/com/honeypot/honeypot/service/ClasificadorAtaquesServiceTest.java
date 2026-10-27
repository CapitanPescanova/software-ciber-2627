package com.honeypot.honeypot.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.honeypot.honeypot.config.FuerzaBrutaConfig;
import com.honeypot.honeypot.repository.LoginAttemptRepository;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ClasificadorAtaquesServiceTest {

    private static final String IP = "203.0.113.10";
    private final Instant ahora = Instant.parse("2026-10-27T12:00:00Z");

    private LoginAttemptRepository repositorio;
    private FuerzaBrutaConfig config;
    private ClasificadorAtaquesService clasificador;

    @BeforeEach
    void preparar() {
        repositorio = mock(LoginAttemptRepository.class);
        config = mock(FuerzaBrutaConfig.class);
        when(config.getMaxIntentos()).thenReturn(5);
        when(config.getVentanaSegundos()).thenReturn(60);
        clasificador = new ClasificadorAtaquesService(repositorio, config);
    }

    @Test
    void elQuintoIntentoEnUnMinutoNoEsFuerzaBruta() {
        when(repositorio.countBySourceIpAndOccurredAtAfter(IP, ahora.minusSeconds(60))).thenReturn(4L);
        assertNull(clasificador.clasificar(IP, ahora));
    }

    @Test
    void elSextoIntentoEnUnMinutoEsFuerzaBruta() {
        when(repositorio.countBySourceIpAndOccurredAtAfter(IP, ahora.minusSeconds(60))).thenReturn(5L);
        assertEquals("fuerza_bruta", clasificador.clasificar(IP, ahora));
    }

    @Test
    void usaLaVentanaDeLaConfiguracion() {
        when(config.getVentanaSegundos()).thenReturn(30);
        clasificador.clasificar(IP, ahora);
        verify(repositorio).countBySourceIpAndOccurredAtAfter(IP, ahora.minusSeconds(30));
    }
}