// Cross-file taint: read tainted globals into sinks
// Expected: cross_file_taint findings

// C01-sink: window.appConfig -> innerHTML
document.getElementById("output").innerHTML = window.appConfig;

// C02-sink: window.analyticsData -> document.write
document.write("<img src='" + window.analyticsData + "'>");
