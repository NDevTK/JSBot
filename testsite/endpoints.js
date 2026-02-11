// Endpoint extraction test cases
// Each should produce an endpoint finding

// E01: fetch call to admin API
fetch("/api/admin/users");

// E02: axios GET to internal config
axios.get("/internal/config/secrets");

// E03: XHR open to API
var xhr = new XMLHttpRequest();
xhr.open("GET", "/api/v1/tokens");

// E04: WebSocket endpoint
var ws = new WebSocket("wss://realtime.example.com/socket");

// E05: fetch with auth endpoint
fetch("/auth/oauth/callback?code=abc");

// E06: GraphQL endpoint
fetch("/graphql/v1/query");

// E07: Webhook endpoint
axios.post("/webhook/stripe/events");
