package com.honeypot.honeypot.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.InetAddress;
import java.net.Socket;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "spring.datasource.url=jdbc:h2:mem:honeypot-scan-test;DB_CLOSE_DELAY=-1",
                "honeypot.ftp.port=2122",
                "honeypot.ssh.port=2223"
        })
@ActiveProfiles("dev")
class DetectorEscaneoServiceTest {

    private static final int FTP_PORT = 2122;
    private static final int SSH_PORT = 2223;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @MockitoBean
    private SiemSenderService siemSenderService;

    @Autowired
    private DetectorEscaneoService detectorEscaneoService;

    @BeforeEach
    void reiniciarDetector() {
        detectorEscaneoService.reiniciarEstado();
    }

    @Test
    void unaSolaConexionFTPSeGuardaYSeEnviaAlSiemComoEscaneo() throws Exception {
        when(siemSenderService.enviarEvento(anyString(), any())).thenReturn(201);

        try (Socket ftp = new Socket("127.0.0.1", FTP_PORT,
                InetAddress.getByName("127.0.0.2"), 0)) {
            assertThat(ftp.isConnected()).isTrue();
        }

        List<Map<String, Object>> scanEvents = esperarEventoPersistido("127.0.0.2");
        assertThat(scanEvents).isNotEmpty();

        Map<String, Object> scanEvent = scanEvents.get(0);
        Long attemptId = ((Number) scanEvent.get("id")).longValue();
        assertThat(scanEvent.get("source_ip")).isEqualTo("127.0.0.2");
        assertThat(scanEvent.get("service_attacked")).isEqualTo("honeypot-scan");
        assertThat(scanEvent.get("tipo_ataque")).isEqualTo("escaneo");
        assertThat(scanEvent.get("attempted_command").toString())
                .contains("ftp")
                .doesNotContain("ssh");

        var jsonCaptor = org.mockito.ArgumentCaptor.forClass(String.class);
        var idCaptor = org.mockito.ArgumentCaptor.forClass(Long.class);
        verify(siemSenderService, timeout(3000).atLeastOnce())
                .enviarEvento(jsonCaptor.capture(), idCaptor.capture());
        assertThat(idCaptor.getAllValues()).contains(attemptId);
        assertThat(jsonCaptor.getAllValues()).anySatisfy(json ->
                assertThat(json)
                        .contains("\"event_id\":\"HP-" + attemptId + "\"")
                        .contains("\"event_type\":\"escaneo\"")
                        .doesNotContain("\"event_type\":\"nmap\""));

        assertThat(esperarMarcadoComoEnviado(attemptId)).isTrue();
    }

    @Test
    void unaSolaConexionSSHSinCredencialesSeGuardaComoEscaneo() throws Exception {
        when(siemSenderService.enviarEvento(anyString(), any())).thenReturn(201);

        try (Socket ssh = new Socket("127.0.0.1", SSH_PORT,
                InetAddress.getByName("127.0.0.3"), 0)) {
            assertThat(ssh.isConnected()).isTrue();
        }

        List<Map<String, Object>> scanEvents = esperarEventoPersistido("127.0.0.3");
        assertThat(scanEvents).isNotEmpty();
        assertThat(scanEvents.get(0).get("attempted_command").toString()).contains("ssh");
        assertThat(scanEvents.get(0).get("attempted_command").toString()).doesNotContain("ftp");
    }

    @Test
    void cerrarFTPDespuesDeEnviarCredencialesNoGeneraEscaneoPorConexionUnica() throws Exception {
        try (Socket ftp = new Socket("127.0.0.1", FTP_PORT,
                InetAddress.getByName("127.0.0.4"), 0);
                var output = ftp.getOutputStream()) {
            output.write("USER test\r\nPASS secreto\r\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            output.flush();
        }

        Thread.sleep(300);
        Long scanEvents = jdbcTemplate.queryForObject(
                "SELECT count(*) FROM login_attempts WHERE source_ip = ? AND tipo_ataque = 'escaneo'",
                Long.class, "127.0.0.4");
        assertThat(scanEvents).isZero();
    }

    @Test
    void escaneoTcpSimuladoConSocketsJavaEnDosPuertosGeneraEvento() throws Exception {
        when(siemSenderService.enviarEvento(anyString(), any())).thenReturn(201);
        try (Socket ftp = new Socket("127.0.0.1", FTP_PORT,
                InetAddress.getByName("127.0.0.5"), 0);
                Socket ssh = new Socket("127.0.0.1", SSH_PORT,
                        InetAddress.getByName("127.0.0.5"), 0)) {
            assertThat(ftp.isConnected()).isTrue();
            assertThat(ssh.isConnected()).isTrue();

            List<Map<String, Object>> scanEvents = esperarEventoPersistido("127.0.0.5");
            assertThat(scanEvents).isNotEmpty();
            assertThat(scanEvents.get(0).get("service_attacked")).isEqualTo("honeypot-scan");
            assertThat(scanEvents.get(0).get("tipo_ataque")).isEqualTo("escaneo");
            assertThat(scanEvents.get(0).get("attempted_command").toString())
                    .contains("ftp")
                    .contains("honeypot-ssh");
        }
    }

    private boolean esperarMarcadoComoEnviado(Long attemptId) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        while (System.nanoTime() < deadline) {
            Boolean enviado = jdbcTemplate.queryForObject(
                    "SELECT enviado FROM login_attempts WHERE id = ?", Boolean.class, attemptId);
            if (Boolean.TRUE.equals(enviado)) {
                return true;
            }
            Thread.sleep(25);
        }
        return false;
    }

    private List<Map<String, Object>> esperarEventoPersistido(String ip) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        List<Map<String, Object>> scanEvents = List.of();
        while (System.nanoTime() < deadline && scanEvents.isEmpty()) {
            scanEvents = jdbcTemplate.queryForList(
                    "SELECT id, source_ip, service_attacked, tipo_ataque, attempted_command "
                            + "FROM login_attempts "
                            + "WHERE source_ip = ? AND service_attacked = 'honeypot-scan' "
                            + "AND tipo_ataque = 'escaneo'",
                    ip
            );
            if (scanEvents.isEmpty()) {
                Thread.sleep(25);
            }
        }
        return scanEvents;
    }

}
