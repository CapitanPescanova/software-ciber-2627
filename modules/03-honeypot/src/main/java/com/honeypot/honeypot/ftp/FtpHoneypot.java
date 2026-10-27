package com.honeypot.honeypot.ftp;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;

import org.apache.ftpserver.FtpServer;
import org.apache.ftpserver.FtpServerFactory;
import org.apache.ftpserver.ftplet.DefaultFtplet;
import org.apache.ftpserver.ftplet.FtpException;
import org.apache.ftpserver.ftplet.FtpRequest;
import org.apache.ftpserver.ftplet.FtpSession;
import org.apache.ftpserver.ftplet.Ftplet;
import org.apache.ftpserver.ftplet.FtpletResult;
import org.apache.ftpserver.ftplet.DefaultFtpReply;
import org.apache.ftpserver.listener.ListenerFactory;
import com.honeypot.honeypot.service.FtpEventService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

@Component
public class FtpHoneypot {
    private static final Logger log = LoggerFactory.getLogger(FtpHoneypot.class);

    private FtpServer server;
    private final FtpEventService ftpEventService;

    public FtpHoneypot(FtpEventService ftpEventService) {
        this.ftpEventService = ftpEventService;
    }

    @PostConstruct
    public void start() {

        try {
            FtpServerFactory serverFactory = new FtpServerFactory();

            ListenerFactory listenerFactory = new ListenerFactory();
            listenerFactory.setPort(2121);

            serverFactory.addListener(
                    "default",
                    listenerFactory.createListener()
            );

            // Comportamiento personalizado del Honeypot
            Map<String, Ftplet> ftplets = new HashMap<>();

            ftplets.put("honeypot", new DefaultFtplet() {
                @Override
                public FtpletResult beforeCommand(
                        FtpSession session,
                        FtpRequest request)
                        throws FtpException, IOException {

                    String command = request.getCommand().toUpperCase(Locale.ROOT);

                    try {
                        String sourceIp = session.getClientAddress().getAddress().getHostAddress();
                        ftpEventService.registrarComando(
                                sourceIp,
                                command,
                                request.getArgument()
                        );
                    } catch (RuntimeException e) {
                        log.error("No se pudo registrar el comando FTP {}", command, e);
                    }

                    if ("USER".equals(command)) {
                        session.write(
                                new DefaultFtpReply(
                                        331,
                                        "User name okay, need password."
                                )
                        );

                        return FtpletResult.SKIP;
                    }

                    if ("PASS".equals(command)) {
                        session.write(
                                new DefaultFtpReply(
                                        530,
                                        "Authentication failed."
                                )
                        );

                        return FtpletResult.SKIP;
                    }

                    return FtpletResult.DEFAULT;
                }
            });

            serverFactory.setFtplets(ftplets);

            server = serverFactory.createServer();
            server.start();

            log.info("FTP HONEYPOT iniciado en puerto 2121");

        } catch (Exception e) {
            log.error("Error iniciando FTP Honeypot", e);
        }
    }

    @PreDestroy
    public void stop() {

        if (server != null) {
            server.stop();
            log.info("FTP HONEYPOT detenido");
        }
    }
}