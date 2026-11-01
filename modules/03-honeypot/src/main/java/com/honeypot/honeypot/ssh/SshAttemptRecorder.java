package com.honeypot.honeypot.ssh;

import com.honeypot.honeypot.config.FuerzaBrutaConfig;
import com.honeypot.honeypot.model.EventoContrato;
import com.honeypot.honeypot.model.LoginAttempt;
import com.honeypot.honeypot.repository.LoginAttemptRepository;
import com.honeypot.honeypot.service.EventoMapper;
import com.honeypot.honeypot.service.SiemSenderService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
// Copia aquí el MISMO import de JsonMapper que usa HoneyPotController
import tools.jackson.databind.json.JsonMapper;

import java.time.Instant;
import java.util.concurrent.CompletableFuture;

@Component
public class SshAttemptRecorder implements SshAttemptListener {

    private static final Logger log = LoggerFactory.getLogger(SshAttemptRecorder.class);

    private static final String SERVICE_NAME = "honeypot-ssh";
    private static final String EVENT_FUERZA_BRUTA = "fuerza_bruta";
    private static final String EVENT_INTENTO = "intento_acceso"; // provisional: confirmar con el equipo del SIEM
    private static final String SEVERITY_FUERZA_BRUTA = "medium";
    private static final String SEVERITY_INTENTO = "low";

    private final LoginAttemptRepository repository;
    private final EventoMapper eventoMapper;
    private final SiemSenderService siemSenderService;
    private final FuerzaBrutaConfig fuerzaBrutaConfig;
    private final JsonMapper jsonMapper = JsonMapper.builder().build();

    public SshAttemptRecorder(LoginAttemptRepository repository,
                              EventoMapper eventoMapper,
                              SiemSenderService siemSenderService,
                              FuerzaBrutaConfig fuerzaBrutaConfig) {
        this.repository = repository;
        this.eventoMapper = eventoMapper;
        this.siemSenderService = siemSenderService;
        this.fuerzaBrutaConfig = fuerzaBrutaConfig;
    }

    @Override
    public void onAttempt(SshAttemptData data) {
        // 1. Guardar primero para que la BD asigne el ID (igual que el login)
        LoginAttempt attempt = toLoginAttempt(data);
        repository.save(attempt);

        // 2. Etiquetar según el umbral, contando intentos de TODOS los servicios
        boolean fuerzaBruta = esFuerzaBruta(attempt);
        String eventType = fuerzaBruta ? EVENT_FUERZA_BRUTA : EVENT_INTENTO;
        String severity = fuerzaBruta ? SEVERITY_FUERZA_BRUTA : SEVERITY_INTENTO;

        // La contraseña no se escribe en el log a propósito
        log.info("Intento SSH guardado: ip={} usuario={} metodo={} tipo={}",
                attempt.getSourceIp(), limpiar(attempt.getUsername()), data.authMethod(), eventType);

        // 3. Envío al SIEM en segundo plano
        enviarAlSiem(attempt, eventType, severity);
    }

    private LoginAttempt toLoginAttempt(SshAttemptData data) {
        LoginAttempt attempt = new LoginAttempt();
        attempt.setSourceIp(data.sourceIp());
        attempt.setOccurredAt(data.occurredAt());
        attempt.setServiceAttacked(SERVICE_NAME);
        attempt.setUsername(truncate(data.username(), 320));
        attempt.setUserAgent(truncate(data.clientVersion(), 512));

        if (data.authMethod() == SshAttemptData.AuthMethod.PASSWORD) {
            attempt.setCredentialAttempt(truncate(data.password(), 2000));
            attempt.setPasswordLength(data.password() == null ? null : data.password().length());
        } else {
            attempt.setCredentialAttempt(truncate(data.publicKeyFingerprint(), 2000));
        }

        // Campos propios de web: no aplican en SSH
        attempt.setRequestPath(null);
        attempt.setAttemptedCommand(null);
        return attempt;
    }

    private boolean esFuerzaBruta(LoginAttempt attempt) {
        if (attempt.getSourceIp() == null) {
            return false;
        }
        Instant desde = attempt.getOccurredAt().minusSeconds(fuerzaBrutaConfig.getVentanaSegundos());
        long intentos = repository.countBySourceIpAndOccurredAtAfter(attempt.getSourceIp(), desde);
        return intentos > fuerzaBrutaConfig.getMaxIntentos();
    }

    private void enviarAlSiem(LoginAttempt attempt, String eventType, String severity) {
        CompletableFuture.runAsync(() -> {
            try {
                EventoContrato evento = eventoMapper.mapearAEvento(attempt, eventType, severity);
                String json = jsonMapper.writeValueAsString(evento);
                int statusCode = siemSenderService.enviarEvento(json);

                if (statusCode == 200 || statusCode == 201) {
                    attempt.setEnviado(true);
                    repository.save(attempt);
                    log.info("Evento {} enviado al SIEM con exito (HTTP {})", evento.eventId(), statusCode);
                } else {
                    log.warn("El SIEM respondio con codigo no exitoso: {} para el evento {}", statusCode, evento.eventId());
                }
            } catch (Exception e) {
                log.warn("Error al procesar o enviar evento SSH al SIEM: {}", e.getMessage());
            }
        });
    }

    private static String truncate(String value, int maxLength) {
        return value == null || value.length() <= maxLength ? value : value.substring(0, maxLength);
    }

    // Evita log injection con usuarios que contengan saltos de línea
    private static String limpiar(String value) {
        return value == null ? null : value.replaceAll("[\\r\\n]", "_");
    }
}
