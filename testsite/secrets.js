// Secret detection test cases
// Each should produce an interesting_string finding

// S01: AWS access key
var awsKey = "AKIAIOSFODNN7EXAMPLE";

// S02: GitHub personal access token
var ghToken = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn";

// S03: Slack bot token
var slackToken = "xoxb-123456789012-1234567890123-ABCdefGHIjklMNOpqrSTUvwx";

// S04: Stripe secret key
var stripeKey = "sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd";

// S05: Stripe publishable key (lower severity)
var stripePub = "pk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd";

// S06: Google API key
var googleKey = "AIzaSyA1234567890abcdefghijklmnopqrstuw";

// S07: JWT token
var token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

// S08: Generic API key
var api_key = "sk-proj-abc123def456ghi789jkl012mno345";

// S09: Debug flag
var debugMode = true;

// S10: Internal IP address
var apiHost = "http://10.0.1.55:8080/api";

// S11: S3 bucket URL
var assetUrl = "https://my-app-assets.s3.us-east-1.amazonaws.com/uploads/config.json";

// S12: Firebase realtime DB
var firebaseUrl = "https://myapp-prod.firebaseio.com/users";

// S13: Security TODO
// TODO: fix auth bypass when token is empty

// S14: Private key (just the header to avoid actual key material)
var pemHeader = "-----BEGIN RSA PRIVATE KEY-----";
