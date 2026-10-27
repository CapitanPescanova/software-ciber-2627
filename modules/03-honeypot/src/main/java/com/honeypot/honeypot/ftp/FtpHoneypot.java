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
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class FtpHoneypot {

    private FtpServer server;

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

                    String command = request.getCommand().toUpperCase();

                    if ("USER".equals(command)) {

                        System.out.println(
                                "FTP USER recibido: " + request.getArgument()
                        );

                        session.write(
                                new DefaultFtpReply(
                                        331,
                                        "User name okay, need password."
                                )
                        );

                        return FtpletResult.SKIP;
                    }

                    if ("PASS".equals(command)) {

                        System.out.println(
                                "FTP PASS recibido"
                        );

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

            System.out.println(
                    "FTP HONEYPOT iniciado en puerto 2121"
            );

        } catch (Exception e) {

            System.err.println(
                    "Error iniciando FTP Honeypot"
            );

            e.printStackTrace();
        }
    }

    @PreDestroy
    public void stop() {

        if (server != null) {
            server.stop();

            System.out.println(
                    "FTP HONEYPOT detenido"
            );
        }
    }
}