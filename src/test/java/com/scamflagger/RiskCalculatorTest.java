package com.scamflagger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class RiskCalculatorTest {
    @Test
    void normalizesUrlsAndDropsFragmentsWithoutChangingEncodedPaths() {
        assertEquals("https://example.com/a?b=1",
                RiskCalculator.normalizeUrl(" HTTPS://Example.COM/a?b=1#section ").toString());
        assertEquals("https://example.com/a%2Fb",
                RiskCalculator.normalizeUrl("https://example.com/a%2Fb").toString());
    }

    @Test
    void rejectsNonWebSchemesCredentialsAndNonstandardPorts() {
        assertThrows(IllegalArgumentException.class, () -> RiskCalculator.normalizeUrl("file:///etc/passwd"));
        assertThrows(IllegalArgumentException.class,
                () -> RiskCalculator.normalizeUrl("https://account@example.com"));
        assertThrows(IllegalArgumentException.class,
                () -> RiskCalculator.normalizeUrl("http://example.com:8080"));
    }

    @Test
    void rejectsPrivateHostsBeforeAnyWebsiteRequest() {
        assertThrows(Exception.class, () -> RiskCalculator.requirePublicHost("localhost"));
        assertThrows(Exception.class, () -> RiskCalculator.requirePublicHost("127.0.0.1"));
        assertThrows(Exception.class, () -> RiskCalculator.requirePublicHost("192.168.1.1"));
    }
}
