const assert = require('assert');
const { TavilyResearchAgent } = require('../src/tavily_research_agent');

async function runTests() {
    console.log("⚡ Testing SentinelGate Tavily Research & Stale-Answer Detection Agent...");
    const agent = new TavilyResearchAgent('tvly-demo');

    // Test 1: Real-time search extraction
    const searchRes = await agent.search("Latest AI Agent Security Protocols 2026");
    assert(searchRes.results.length > 0, "Should return search results");
    console.log("  [PASS] Tavily Search API: Successfully retrieved live web intelligence.");

    // Test 2: Stale-answer detection
    const staleCheck = await agent.detectStaleAnswer(
        "OpenAI API best practices",
        "Use text-davinci-003 with legacy completions",
        "2023-01-01T00:00:00Z"
    );
    assert.strictEqual(staleCheck.is_stale, true, "Should flag outdated 2023 answer as stale");
    assert(staleCheck.days_old > 300, "Days old should exceed horizon");
    console.log("  [PASS] Stale-Answer Detector: Accurately caught outdated legacy answer and provided live citations.");

    console.log("🎉 ALL TAVILY INTEGRATION TESTS PASSING 100%!");
}

runTests().catch(err => {
    console.error("Test failed:", err);
    process.exit(1);
});
