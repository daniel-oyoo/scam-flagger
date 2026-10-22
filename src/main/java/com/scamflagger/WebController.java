package com.scamflagger;

import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class WebController {
    private final DataStore dataStore;
    private final PasswordService passwordService;
    private final RiskCalculator riskCalculator;

    public WebController(DataStore dataStore, PasswordService passwordService,
                         RiskCalculator riskCalculator) {
        this.dataStore = dataStore;
        this.passwordService = passwordService;
        this.riskCalculator = riskCalculator;
    }

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/register")
    public String registerPage() {
        return "register";
    }

    @PostMapping("/register")
    public String register(@RequestParam String username,
                           @RequestParam String email,
                           @RequestParam String password,
                           RedirectAttributes redirect) {
        String normalizedUsername = username.trim();
        String normalizedEmail = email.trim();
        if (normalizedUsername.isEmpty() || normalizedEmail.isEmpty() || password.isBlank()
                || normalizedUsername.length() > 80 || normalizedEmail.length() > 254
                || password.length() > 256 || !normalizedEmail.matches("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$")) {
            redirect.addFlashAttribute("flashMessage", "Please enter a valid username, email, and password.");
            redirect.addFlashAttribute("flashCategory", "danger");
            return "redirect:/register";
        }
        if (!dataStore.createUser(normalizedUsername, normalizedEmail, passwordService.encode(password))) {
            redirect.addFlashAttribute("flashMessage", "Username or email already exists.");
            redirect.addFlashAttribute("flashCategory", "danger");
            return "redirect:/register";
        }
        redirect.addFlashAttribute("flashMessage", "Registration successful! Please log in.");
        redirect.addFlashAttribute("flashCategory", "success");
        return "redirect:/login";
    }

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @PostMapping("/login")
    public String login(@RequestParam String username,
                        @RequestParam String password,
                        HttpServletRequest request,
                        RedirectAttributes redirect) {
        Optional<User> user = dataStore.findUserByUsername(username.trim())
                .filter(candidate -> passwordService.matches(password, candidate.passwordHash()));
        if (user.isEmpty()) {
            redirect.addFlashAttribute("flashMessage", "Invalid username or password.");
            redirect.addFlashAttribute("flashCategory", "danger");
            return "redirect:/login";
        }
        HttpSession oldSession = request.getSession(false);
        if (oldSession != null) {
            oldSession.invalidate();
        }
        HttpSession session = request.getSession(true);
        session.setAttribute("userId", user.get().id());
        session.setAttribute("username", user.get().username());
        redirect.addFlashAttribute("flashMessage", "Login successful!");
        redirect.addFlashAttribute("flashCategory", "success");
        return "redirect:/";
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request, RedirectAttributes redirect) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        redirect.addFlashAttribute("flashMessage", "You have been logged out.");
        redirect.addFlashAttribute("flashCategory", "success");
        return "redirect:/";
    }

    @GetMapping("/check")
    public String checkPage(@RequestParam(required = false) Long websiteId,
                            HttpSession session,
                            Model model,
                            RedirectAttributes redirect) {
        if (!isLoggedIn(session)) {
            redirect.addFlashAttribute("flashMessage", "Please log in to check websites.");
            redirect.addFlashAttribute("flashCategory", "danger");
            return "redirect:/login";
        }
        if (websiteId == null) {
            return "check";
        }
        Optional<Website> website = dataStore.findWebsiteById(websiteId);
        if (website.isEmpty()) {
            redirect.addFlashAttribute("flashMessage", "Website not found.");
            redirect.addFlashAttribute("flashCategory", "danger");
            return "redirect:/check";
        }
        addResultToModel(model, website.get(), java.util.List.of());
        return "result";
    }

    @PostMapping("/check")
    public String checkWebsite(@RequestParam String url, HttpSession session, Model model,
                               RedirectAttributes redirect) {
        if (!isLoggedIn(session)) {
            redirect.addFlashAttribute("flashMessage", "Please log in to check websites.");
            redirect.addFlashAttribute("flashCategory", "danger");
            return "redirect:/login";
        }
        String submittedUrl = url.trim();
        String normalizedUrl;
        try {
            normalizedUrl = RiskCalculator.normalizeUrl(submittedUrl).toString();
        } catch (IllegalArgumentException exception) {
            redirect.addFlashAttribute("flashMessage", "Please enter a valid HTTP or HTTPS website URL.");
            redirect.addFlashAttribute("flashCategory", "danger");
            return "redirect:/check";
        }
        Optional<Website> cachedWebsite = dataStore.findWebsiteByUrl(submittedUrl);
        if (cachedWebsite.isEmpty() && !submittedUrl.equals(normalizedUrl)) {
            cachedWebsite = dataStore.findWebsiteByUrl(normalizedUrl);
        }
        Website website;
        java.util.List<String> flags;
        if (cachedWebsite.isPresent()) {
            website = cachedWebsite.get();
            flags = java.util.List.of();
            model.addAttribute("flashMessage", "Website found in database.");
            model.addAttribute("flashCategory", "info");
        } else {
            WebsiteAnalysis analysis = riskCalculator.calculateRisk(normalizedUrl);
            website = dataStore.saveWebsiteAnalysis(normalizedUrl, analysis.riskScore());
            flags = analysis.triggeredFlags();
            model.addAttribute("flashMessage", "Website analysis completed!");
            model.addAttribute("flashCategory", "success");
        }
        addResultToModel(model, website, flags);
        return "result";
    }

    @PostMapping("/review")
    public String addReview(@RequestParam long websiteId,
                            @RequestParam int rating,
                            @RequestParam String comment,
                            HttpSession session,
                            RedirectAttributes redirect) {
        if (!isLoggedIn(session)) {
            redirect.addFlashAttribute("flashMessage", "Please log in to add reviews.");
            redirect.addFlashAttribute("flashCategory", "danger");
            return "redirect:/login";
        }
        if (rating < 1 || rating > 5 || comment.isBlank() || comment.length() > 2000
                || dataStore.findWebsiteById(websiteId).isEmpty()) {
            redirect.addFlashAttribute("flashMessage", "Please provide a valid rating and review.");
            redirect.addFlashAttribute("flashCategory", "danger");
            return "redirect:/check";
        }
        dataStore.createReview((Long) session.getAttribute("userId"), websiteId,
                rating, comment.trim());
        redirect.addFlashAttribute("flashMessage", "Review added successfully!");
        redirect.addFlashAttribute("flashCategory", "success");
        return "redirect:/check?websiteId=" + websiteId;
    }

    private void addResultToModel(Model model, Website website, java.util.List<String> flags) {
        model.addAttribute("website", website);
        model.addAttribute("triggeredFlags", flags);
        model.addAttribute("reviews", dataStore.findReviews(website.id()));
    }

    private static boolean isLoggedIn(HttpSession session) {
        return session.getAttribute("userId") instanceof Long;
    }
}

@ControllerAdvice
class PageModelAdvice {
    @ModelAttribute
    public void addCurrentUser(HttpSession session, Model model) {
        model.addAttribute("loggedIn", session.getAttribute("userId") instanceof Long);
        model.addAttribute("currentUsername", session.getAttribute("username"));
    }

    @ExceptionHandler(org.springframework.web.bind.MissingServletRequestParameterException.class)
    public String missingParameter(RedirectAttributes redirect) {
        redirect.addFlashAttribute("flashMessage", "Please complete all required fields.");
        redirect.addFlashAttribute("flashCategory", "danger");
        return "redirect:/";
    }
}
