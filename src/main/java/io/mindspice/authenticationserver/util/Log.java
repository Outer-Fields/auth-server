package io.mindspice.authenticationserver.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.stream.Collectors;


public enum Log {
    SERVER(LoggerFactory.getLogger("APP")),
    ABUSE(LoggerFactory.getLogger("ABUSE"));



    private Logger logger;

    Log(Logger logger) {
        this.logger = logger;
    }

    public void error(Class<?> clazz, String msg, Exception ex) {
        logger.error("{} | From class: {} | Exception: {}", msg, clazz.getSimpleName(), ex.getMessage(), ex);
    }

    public void error(Class<?> clazz, String msg) {
        logger.error("{} | From class: {}", msg, clazz.getSimpleName());
    }

    public void error(Class<?> clazz, Exception ex) {
        logger.error("Error | From class: {} | Exception: {}", clazz.getSimpleName(), ex.getMessage(), ex);
    }

    public void info(Class<?> clazz, String msg) {
        logger.info("{} | From class: {}", msg, clazz.getSimpleName());
    }

    public void info(String msg) {
        logger.info(msg);
    }

    public void info(Class<?> clazz) {
        logger.info("Info | From class: {}", clazz.getSimpleName());
    }

    public void debug(Class<?> clazz, String msg, Exception ex) {
        logger.debug("{} | From class: {} | Exception: {}", msg, clazz.getSimpleName(), ex.getMessage(), ex);
    }

    public void debug(Class<?> clazz, String msg) {
        logger.debug("{} | From class: {}", msg, clazz.getSimpleName());
    }

    public void debug(Class<?> clazz, Exception ex) {
        logger.debug("Debug | From class: {} | Exception: {}", clazz.getSimpleName(), ex.getMessage(), ex);
    }

    public void logStackTrace() {
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
        String log = Arrays.stream(stackTrace)
                .filter(s -> !s.getClassName().contains("junit"))
                .map(e -> e.getClassName() + ":" + e.getLineNumber() + ":"  + e.getMethodName())
                .collect(Collectors.joining("\n"));
        logger.debug("Advance Debug Trace: {}" , log);
    }
}

