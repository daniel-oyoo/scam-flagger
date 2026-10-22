package com.scamflagger;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class RiskCalculator {
    private static final Logger logger = LoggerFactory.getLogger(RiskCalculator.class);
    private static final List<String> HIGH_RISK_KEYWORDS = List.of(
            "guaranteed daily return", "double your investment", "passive income",
            "no risk", "get rich quick", "instant wealth", "financial freedom",
            "crypto investment", "bitcoin mining", "high returns", "risk-free",
            "guaranteed profit", "make money fast", "easy money");
    private static final List<String> CONTACT_INDICATORS =
            List.of("contact", "about", "address", "phone", "email", "location", "support", "help");
    private static final List<String> TESTIMONIAL_INDICATORS =
            List.of("testimonial", "review", "success story", "what our clients say");
    private static final Pattern EMAIL = Pattern.compile(
            "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b");
    private static final Pattern PHONE = Pattern.compile(
            "(\\+?\\d{1,3}[-.\\s]?)?\\(?\\d{3}\\)?[-.\\s]?\\d{3}[-.\\s]?\\d{4}");
    private static final Pattern ADDRESS = Pattern.compile(
            "\\d+\\s+[\\w\\s]+,?\\s*\\w+,\\s*\\w+\\s+\\d+|p\\.?o\\.?\\s+box",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern WHOIS_SERVER =
            Pattern.compile("(?im)^whois:\\s*(\\S+)");
    private static final Pattern CREATION_DATE = Pattern.compile(
            "(?im)^(?:creation date|created|created on|registration time|registered):\\s*(.+)$");
    private static final Set<DateTimeFormatter> WHOIS_DATE_FORMATS = Set.of(
            DateTimeFormatter.ISO_DATE_TIME,
            DateTimeFormatter.ISO_LOCAL_DATE,
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssX", Locale.ROOT),
            DateTimeFormatter.ofPattern("yyyy-MM-dd", Locale.ROOT));

    public WebsiteAnalysis calculateRisk(String input) {
        List<String> flags = new ArrayList<>();
        try {
            URI uri = normalizeUrl(input);
            Document page = fetchPublicPage(uri);
            String text = page.text().toLowerCase(Locale.ROOT);
            int score = 0;

            int keywordScore = checkKeywords(text);
            score += addFlag(flags, keywordScore, "High-risk keywords detected");

            int contactScore = checkContactInfo(page, text);
            score += addFlag(flags, contactScore, "Lack of contact information");

            int domainScore = checkDomainAge(uri.getHost());
            score += addFlag(flags, domainScore, "New domain registration");

            int sslScore = checkSsl(uri);
            score += addFlag(flags, sslScore, "SSL security issues");

            int socialScore = checkSocialProof(page);
            score += addFlag(flags, socialScore, "Potential fake social proof");

            int designScore = checkDesign(page, text);
            score += addFlag(flags, designScore, "Unprofessional design indicators");
            return new WebsiteAnalysis(Math.min(score, 100), List.copyOf(flags));
        } catch (Exception exception) {
            logger.warn("Could not analyze website URL", exception);
            return new WebsiteAnalysis(50, List.of("Website inaccessible (+50)"));
        }
    }

    static URI normalizeUrl(String input) {
        if (input == null || input.isBlank()) {
            throw new IllegalArgumentException("Website URL is required");
        }
        String value = input.trim();
        if (value.matches("(?i)^[a-z][a-z0-9+.-]*:.*")
                && !value.matches("(?i)^https?://.*")) {
            throw new IllegalArgumentException("Only HTTP and HTTPS website URLs are supported");
        }
        if (!value.matches("(?i)^https?://.*")) {
            value = "https://" + value;
        }
        URI uri = URI.create(value);
        if (uri.getHost() == null || (!uri.getScheme().equalsIgnoreCase("https")
                && !uri.getScheme().equalsIgnoreCase("http"))) {
            throw new IllegalArgumentException("Only HTTP and HTTPS website URLs are supported");
        }
        if (uri.getUserInfo() != null) {
            throw new IllegalArgumentException("Credentials in website URLs are not supported");
        }
        int defaultPort = uri.getScheme().equalsIgnoreCase("https") ? 443 : 80;
        if (uri.getPort() != -1 && uri.getPort() != defaultPort) {
            throw new IllegalArgumentException("Only standard HTTP and HTTPS ports are supported");
        }
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        if (host.contains(":") && !host.startsWith("[")) {
            host = "[" + host + "]";
        }
        String path = uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        String query = uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery();
        URI normalized = URI.create(uri.getScheme().toLowerCase(Locale.ROOT) + "://"
                + host + path + query).normalize();
        if (normalized.toString().length() > 700) {
            throw new IllegalArgumentException("Website URL must be 700 characters or fewer");
        }
        return normalized;
    }

    private static Document fetchPublicPage(URI initialUri) throws Exception {
        URI uri = initialUri;
        for (int redirects = 0; redirects <= 5; redirects++) {
            requirePublicHost(uri.getHost());
            org.jsoup.Connection.Response response = Jsoup.connect(uri.toString())
                    .userAgent("Mozilla/5.0 (compatible; ScamFlagger/1.0)")
                    .timeout(10_000)
                    .followRedirects(false)
                    .execute();
            int status = response.statusCode();
            if (status >= 300 && status < 400) {
                String location = response.header("Location");
                if (location == null || redirects == 5) {
                    throw new IllegalArgumentException("Website returned an invalid redirect");
                }
                uri = normalizeUrl(uri.resolve(location).toString());
                continue;
            }
            if (status < 200 || status >= 400) {
                throw new IllegalArgumentException("Website returned HTTP " + status);
            }
            return response.parse();
        }
        throw new IllegalArgumentException("Website redirected too many times");
    }

    static void requirePublicHost(String host) throws Exception {
        for (InetAddress address : InetAddress.getAllByName(host)) {
            byte[] bytes = address.getAddress();
            if (address.isAnyLocalAddress() || address.isLoopbackAddress()
                    || address.isLinkLocalAddress() || address.isSiteLocalAddress()
                    || address.isMulticastAddress()
                    || (address instanceof Inet4Address && !isPublicIpv4(bytes))
                    || (address instanceof Inet6Address && !isPublicIpv6(bytes))) {
                throw new IllegalArgumentException("Website host must resolve to public IP addresses");
            }
        }
    }

    private static boolean isPublicIpv4(byte[] address) {
        int first = Byte.toUnsignedInt(address[0]);
        int second = Byte.toUnsignedInt(address[1]);
        int third = Byte.toUnsignedInt(address[2]);
        return first != 0 && first != 10 && first != 127 && first < 224
                && !(first == 100 && second >= 64 && second <= 127)
                && !(first == 169 && second == 254)
                && !(first == 172 && second >= 16 && second <= 31)
                && !(first == 192 && (second == 168
                        || (second == 0 && (third == 0 || third == 2))
                        || (second == 88 && third == 99)))
                && !(first == 198 && (second == 18 || second == 19
                        || (second == 51 && third == 100)))
                && !(first == 203 && second == 0 && third == 113);
    }

    private static boolean isPublicIpv6(byte[] address) {
        int first = Byte.toUnsignedInt(address[0]);
        int second = Byte.toUnsignedInt(address[1]);
        boolean globalUnicast = (first & 0xE0) == 0x20;
        boolean documentation = first == 0x20 && second == 0x01
                && Byte.toUnsignedInt(address[2]) == 0x0D
                && Byte.toUnsignedInt(address[3]) == 0xB8;
        return globalUnicast && !documentation;
    }

    private static int checkKeywords(String text) {
        int count = 0;
        for (String keyword : HIGH_RISK_KEYWORDS) {
            if (text.contains(keyword)) {
                count += 5;
            }
        }
        return Math.min(count, 20);
    }

    private static int checkContactInfo(Document page, String text) {
        long contactLinks = page.select("a[href]").stream()
                .filter(link -> containsAny(link.text().toLowerCase(Locale.ROOT), CONTACT_INDICATORS))
                .count();
        boolean hasAddress = ADDRESS.matcher(text).find();
        boolean hasPhone = PHONE.matcher(text).find();
        boolean hasEmail = EMAIL.matcher(text).find();
        if (contactLinks == 0 && !hasAddress && !hasPhone && !hasEmail) {
            return 15;
        }
        return ((contactLinks == 0 && !hasAddress) || (!hasPhone && !hasEmail)) ? 10 : 0;
    }

    private static int checkDomainAge(String host) {
        try {
            requirePublicHost(host);
            String response = whois(host, "whois.iana.org");
            Matcher server = WHOIS_SERVER.matcher(response);
            if (server.find()) {
                response = whois(host, server.group(1));
            }
            Matcher creation = CREATION_DATE.matcher(response);
            if (!creation.find()) {
                return 0;
            }
            LocalDate created = parseWhoisDate(creation.group(1));
            long ageDays = LocalDate.now(ZoneOffset.UTC).toEpochDay() - created.toEpochDay();
            if (ageDays <= 180) {
                return 15;
            }
            return ageDays <= 365 ? 10 : 0;
        } catch (Exception exception) {
            return 10;
        }
    }

    private static String whois(String domain, String server) throws Exception {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(server, 43), 2500);
            socket.setSoTimeout(2500);
            socket.getOutputStream().write((domain + "\r\n").getBytes(StandardCharsets.US_ASCII));
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8))) {
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null && response.length() < 64_000) {
                    response.append(line).append('\n');
                }
                return response.toString();
            }
        }
    }

    private static LocalDate parseWhoisDate(String value) {
        String date = value.trim().split("\\s+")[0];
        for (DateTimeFormatter formatter : WHOIS_DATE_FORMATS) {
            try {
                return LocalDate.parse(date, formatter);
            } catch (DateTimeParseException ignored) {
                try {
                    return LocalDate.parse(date.substring(0, 10), DateTimeFormatter.ISO_LOCAL_DATE);
                } catch (RuntimeException ignoredAgain) {
                    // Try the next common WHOIS date format.
                }
            }
        }
        throw new IllegalArgumentException("Unsupported WHOIS creation date");
    }

    private static int checkSsl(URI uri) {
        if (!uri.getScheme().equalsIgnoreCase("https")) {
            return 10;
        }
        try (Socket raw = new Socket()) {
            requirePublicHost(uri.getHost());
            int port = uri.getPort() > 0 ? uri.getPort() : 443;
            raw.connect(new InetSocketAddress(uri.getHost(), port), 5000);
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            try (SSLSocket ssl = (SSLSocket) factory.createSocket(raw, uri.getHost(), port, true)) {
                ssl.setSoTimeout(5000);
                ssl.startHandshake();
                for (Certificate certificate : ssl.getSession().getPeerCertificates()) {
                    if (certificate instanceof X509Certificate x509
                            && x509.getNotAfter().toInstant().isBefore(
                                    java.time.Instant.now().plusSeconds(30L * 24 * 60 * 60))) {
                        return 5;
                    }
                }
                return 0;
            }
        } catch (Exception exception) {
            return 10;
        }
    }

    private static int checkSocialProof(Document page) {
        List<Element> testimonials = page.select("div[class], section[class]").stream()
                .filter(element -> containsAny(element.className().toLowerCase(Locale.ROOT),
                        TESTIMONIAL_INDICATORS))
                .toList();
        if (testimonials.isEmpty()) {
            return 0;
        }
        String text = testimonials.stream().map(Element::text).reduce("", (a, b) -> a + " " + b)
                .toLowerCase(Locale.ROOT);
        if (List.of("john doe", "jane smith", "customer", "client").stream().anyMatch(text::contains)) {
            return 10;
        }
        if (testimonials.size() > 10) {
            return 8;
        }
        return countOccurrences(text, "amazing") > 3 ? 6 : 0;
    }

    private static int checkDesign(Document page, String text) {
        String[] words = text.split("\\s+");
        long uppercase = java.util.Arrays.stream(words)
                .filter(word -> word.length() > 1 && word.equals(word.toUpperCase(Locale.ROOT)))
                .count();
        int score = uppercase > words.length * 0.1 ? 3 : 0;
        long grammarIssues = countOccurrences(text, "!!") + countOccurrences(text, "???");
        if (grammarIssues > 5) {
            score += 3;
        }
        List<Element> images = page.select("img");
        long lowResolution = images.stream().filter(image ->
                isSmallDimension(image, "width") || isSmallDimension(image, "height")).count();
        if (!images.isEmpty() && lowResolution > images.size() * 0.5) {
            score += 4;
        }
        return Math.min(score, 10);
    }

    private static boolean isSmallDimension(Element image, String dimension) {
        try {
            String value = image.attr(dimension);
            return !value.isBlank() && Integer.parseInt(value) < 100;
        } catch (NumberFormatException exception) {
            return false;
        }
    }

    private static boolean containsAny(String text, List<String> candidates) {
        return candidates.stream().anyMatch(text::contains);
    }

    private static long countOccurrences(String text, String value) {
        return (text.length() - text.replace(value, "").length()) / value.length();
    }

    private static int addFlag(List<String> flags, int score, String description) {
        if (score > 0) {
            flags.add(description + " (+" + score + ")");
        }
        return score;
    }
}
