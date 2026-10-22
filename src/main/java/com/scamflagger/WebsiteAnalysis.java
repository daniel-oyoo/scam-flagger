package com.scamflagger;

import java.util.List;

public record WebsiteAnalysis(int riskScore, List<String> triggeredFlags) {
}
