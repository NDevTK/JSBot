// Cross-file taint: write tainted globals
// Expected: cross_file_taint finding when paired with globals-reader.js

// C01: location.hash -> window.appConfig
window.appConfig = location.hash.slice(1);

// C02: document.referrer -> window.analyticsData
window.analyticsData = document.referrer;

// C03: Dangerous global function that calls eval
window.processTemplate = function(tpl) {
    eval("var result = " + tpl);
    return result;
};
