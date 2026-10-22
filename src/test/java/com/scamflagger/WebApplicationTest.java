package com.scamflagger;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;

import jakarta.servlet.http.HttpSession;
import org.springframework.jdbc.core.JdbcTemplate;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class WebApplicationTest {
    @Autowired
    private MockMvc mvc;

    @Autowired
    private DataStore dataStore;

    @Autowired
    private JdbcTemplate jdbc;

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry properties) {
        properties.add("spring.datasource.url", () -> "jdbc:sqlite:target/scam-flagger-test.db");
        properties.add("spring.thymeleaf.cache", () -> "false");
    }

    @Test
    void rendersHomeAndProtectsWebsiteChecks() throws Exception {
        mvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Scam Flagger")));
        mvc.perform(get("/check"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));
    }

    @Test
    void registersLogsInAndCanReviewAWebsite() throws Exception {
        String username = "test-" + UUID.randomUUID();
        mvc.perform(post("/register")
                        .param("username", username)
                        .param("email", username + "@example.com")
                        .param("password", "test-password"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));
        mvc.perform(post("/register")
                        .param("username", username)
                        .param("email", "another-" + username + "@example.com")
                        .param("password", "test-password"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/register"));

        MvcResult login = mvc.perform(post("/login")
                        .param("username", username)
                        .param("password", "test-password"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/"))
                .andReturn();
        HttpSession session = login.getRequest().getSession(false);

        mvc.perform(get("/check").session((org.springframework.mock.web.MockHttpSession) session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Check Website for Scams")));

        String legacyUrl = "legacy-" + UUID.randomUUID() + ".example";
        jdbc.update("INSERT INTO websites (url, risk_score, flagged) VALUES (?, ?, ?)",
                legacyUrl, 25, false);
        mvc.perform(post("/check")
                        .session((org.springframework.mock.web.MockHttpSession) session)
                        .param("url", legacyUrl))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Website found in database.")));

        Website website = dataStore.saveWebsiteAnalysis("https://example.test", 30);
        Website updatedWebsite = dataStore.saveWebsiteAnalysis("https://example.test", 75);
        assertEquals(website.id(), updatedWebsite.id());
        assertEquals(75, updatedWebsite.riskScore());
        assertTrue(updatedWebsite.flagged());
        mvc.perform(post("/review")
                        .session((org.springframework.mock.web.MockHttpSession) session)
                        .param("websiteId", Long.toString(website.id()))
                        .param("rating", "5")
                        .param("comment", "Looks good"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/check?websiteId=" + website.id()));

        mvc.perform(get("/check")
                        .session((org.springframework.mock.web.MockHttpSession) session)
                        .param("websiteId", Long.toString(website.id())))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Looks good")));
    }
}
