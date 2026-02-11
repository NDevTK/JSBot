// postMessage handler test cases

// P01: No origin check at all — message data into innerHTML
window.addEventListener("message", function(e) {
    var content = e.data;
    document.getElementById("output").innerHTML = content;
});

// P02: Weak origin check (indexOf) — message data into eval
window.onmessage = function(event) {
    if (event.origin.indexOf("trusted.com") > -1) {
        eval(event.data);
    }
};

// P03: postMessage with .source check but still sinks data
window.addEventListener("message", function(msg) {
    if (msg.source === window.parent) {
        document.write(msg.data);
    }
});
