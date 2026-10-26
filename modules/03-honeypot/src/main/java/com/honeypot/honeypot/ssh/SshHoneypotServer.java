package com.honeypot.honeypot.ssh;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.pubkey.RejectAllPublickeyAuthenticator;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Paths;

@Component
public class SshHoneypotServer {

    private static final Logger log = LoggerFactory.getLogger(SshHoneypotServer.class);

    @Value("${honeypot.ssh.port:2222}")
    private int port;

    @Value("${honeypot.ssh.version:OpenSSH_8.9p1 Ubuntu-3ubuntu0.6}")
    private String serverVersion;

    @Value("${honeypot.ssh.hostkey:hostkey.ser}")
    private String hostKeyPath;

    private SshServer sshd;

    @PostConstruct
    public void start() throws IOException {
        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);

        // Clave de host persistente (si cambiara en cada arranque, sería sospechoso)
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(Paths.get(hostKeyPath)));

        // Banner: el cliente recibe "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        CoreModuleProperties.SERVER_IDENTIFICATION.set(sshd, serverVersion);

        // Pide contraseña y SIEMPRE la rechaza
        sshd.setPasswordAuthenticator((username, password, session) -> {
            log.info("Intento SSH rechazado - usuario: {} desde {}", username, session.getClientAddress());
            return false;
        });

        // Rechaza también la autenticación por clave pública
        sshd.setPublickeyAuthenticator(RejectAllPublickeyAuthenticator.INSTANCE);

        sshd.start();
        log.info("Honeypot SSH escuchando en el puerto {}", port);
    }

    @PreDestroy
    public void stop() throws IOException {
        if (sshd != null) {
            sshd.stop();
        }
    }
}