// main.js

const { DNSServer, DNSBackend } = require("./dns-server");
const winston = require("winston");

// Setup logger (ensure logger is accessible here if needed)
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: "dns-server.log" }),
  ],
});

// Instantiate and start the DNS Server
const dnsServer = new DNSServer();
dnsServer.start();

// Instantiate the DNS Backend API
const dnsBackend = new DNSBackend();

// Graceful shutdown
process.on("SIGINT", async () => {
  logger.info("Received SIGINT. Shutting down...");
  await dnsServer.stop();
  process.exit(0);
});

process.on("SIGTERM", async () => {
  logger.info("Received SIGTERM. Shutting down...");
  await dnsServer.stop();
  process.exit(0);
});
