// dns-server.js

const dgram = require("node:dgram");
const dnsPacket = require("dns-packet");
const Redis = require("ioredis");
const winston = require("winston");
const net = require("net");
const punycode = require("punycode");
const express = require("express");
const bodyParser = require("body-parser");

// Define DNS RCODE constants
const RCODE_NOERROR = 0;
const RCODE_SERVFAIL = 2;
const RCODE_NXDOMAIN = 3;

// Define DNS Flags
const FLAGS = {
  QR: 1 << 15, // Query/Response Flag
  OPCODE: 0 << 11, // Standard Query
  AA: 1 << 10, // Authoritative Answer
  TC: 1 << 9, // Truncated
  RD: 1 << 8, // Recursion Desired
  RA: 1 << 7, // Recursion Available
  Z: 0 << 4, // Reserved
};

// Define RCODE to Name mapping
const RCODE_TO_NAME = {
  0: "NOERROR",
  1: "FORMERR",
  2: "SERVFAIL",
  3: "NXDOMAIN",
  4: "NOTIMP",
  5: "REFUSED",
  // Add more RCODEs as needed
};

// Setup logger
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

class DNSServer {
  constructor() {
    this.server = dgram.createSocket("udp4");
    this.redis = new Redis({
      host: process.env.REDIS_HOST || "localhost",
      port: process.env.REDIS_PORT || 6379,
    });

    this.redis.on("error", (err) =>
      logger.error("Redis Client Error", { error: err.message })
    );

    this.server.on("message", this.handleMessage.bind(this));
    this.server.on("error", this.handleError.bind(this));
  }

  handleError(error) {
    logger.error("DNS Server Error", { error: error.message });
    if (error.code === "EADDRINUSE") {
      logger.info("Attempting to bind to another port...");
      this.start(this.port + 1);
    }
  }

  async handleMessage(msg, rinfo) {
    try {
      const request = dnsPacket.decode(msg);
      logger.info("Received DNS query", {
        id: request.id,
        questions: request.questions,
      });

      if (!request.questions || request.questions.length === 0) {
        throw new Error("No questions in DNS query");
      }

      const domain = request.questions[0].name;
      const queryType = request.questions[0].type.toUpperCase();

      const recordData = await this.redis.hget(domain, queryType);
      logger.info("Redis lookup result", { domain, queryType, recordData });

      let response;
      if (recordData) {
        const parsedData = JSON.parse(recordData);
        response = this.createSuccessResponse(
          request,
          domain,
          queryType,
          parsedData
        );
      } else {
        logger.info(`No record found`, { domain, queryType });
        response = this.createNXDOMAINResponse(request, domain);
      }

      const encodedResponse = dnsPacket.encode(response);
      this.server.send(encodedResponse, rinfo.port, rinfo.address, (error) => {
        if (error) {
          logger.error("Error sending DNS response", { error: error.message });
        } else {
          const rcode = RCODE_TO_NAME[response.flags & 0xf] || "UNKNOWN";
          logger.info("Sent DNS response", {
            id: response.id,
            rcode: rcode,
            to: `${rinfo.address}:${rinfo.port}`,
          });
        }
      });
    } catch (error) {
      logger.error("Error processing DNS query", {
        error: error.message,
        stack: error.stack,
      });
      // Optionally, send a SERVFAIL response
      try {
        const request = dnsPacket.decode(msg);
        const response = {
          type: "response",
          id: request.id,
          flags: FLAGS.QR | FLAGS.RD | RCODE_SERVFAIL,
          questions: request.questions || [],
          answers: [],
        };
        const encodedResponse = dnsPacket.encode(response);
        this.server.send(encodedResponse, rinfo.port, rinfo.address);
        logger.info("Sent SERVFAIL response", {
          id: request.id,
          to: `${rinfo.address}:${rinfo.port}`,
        });
      } catch (e) {
        logger.error("Failed to send SERVFAIL response", { error: e.message });
      }
    }
  }

  createSuccessResponse(request, domain, queryType, data) {
    return {
      type: "response",
      id: request.id,
      flags: FLAGS.QR | FLAGS.AA | FLAGS.RD | RCODE_NOERROR,
      questions: request.questions,
      answers: [
        {
          type: queryType,
          class: "IN",
          name: domain,
          ttl: 300, // 5 minutes TTL
          data: this.formatRecordData(queryType, data),
        },
      ],
    };
  }

  formatRecordData(queryType, data) {
    switch (queryType) {
      case "A":
      case "AAAA":
      case "NS":
      case "CNAME":
      case "PTR":
      case "TXT":
        return data;
      case "MX":
        return { preference: data.preference, exchange: data.exchange };
      case "SOA":
        return {
          mname: data.mname,
          rname: data.rname,
          serial: data.serial,
          refresh: data.refresh,
          retry: data.retry,
          expire: data.expire,
          minimum: data.minimum,
        };
      case "SRV":
        return {
          priority: data.priority,
          weight: data.weight,
          port: data.port,
          target: data.target,
        };
      case "CAA":
        return {
          flags: data.flags,
          tag: data.tag,
          value: data.value,
        };
      default:
        return data;
    }
  }

  createNXDOMAINResponse(request, domain) {
    return {
      type: "response",
      id: request.id,
      flags: FLAGS.QR | FLAGS.AA | RCODE_NXDOMAIN,
      questions: request.questions,
      answers: [],
      authorities: [
        {
          type: "SOA",
          name: domain,
          ttl: 600,
          data: {
            mname: "ns1.example.com",
            rname: "admin.example.com",
            serial: Math.floor(Date.now() / 1000),
            refresh: 1800,
            retry: 600,
            expire: 86400,
            minimum: 3600,
          },
        },
      ],
    };
  }

  start(port = process.env.DNS_PORT || 53) {
    this.port = port;
    this.server.bind(this.port, () =>
      logger.info(`DNS Server is running on port ${this.port}`)
    );
  }

  stop() {
    return new Promise((resolve) => {
      logger.info("Shutting down DNS server...");
      this.server.close(() => {
        logger.info("DNS server closed");
        this.redis.quit();
        resolve();
      });
    });
  }
}

class DNSBackend {
  constructor() {
    this.redis = new Redis({
      host: process.env.REDIS_HOST || "localhost",
      port: process.env.REDIS_PORT || 6379,
    });

    this.redis.on("error", (err) =>
      logger.error("Redis Client Error", { error: err.message })
    );

    this.app = express();
    this.app.use(bodyParser.json());

    // Define routes
    this.app.post("/dns/:domain", this.addDNSRecord.bind(this));
    this.app.get("/dns/:domain", this.getDNSRecords.bind(this));
    this.app.delete(
      "/dns/:domain/:recordType",
      this.deleteDNSRecord.bind(this)
    );
    this.app.get("/domains", this.listDomains.bind(this));

    // Start the server
    const port = process.env.BACKEND_PORT || 3000;
    this.app.listen(port, () => {
      logger.info(`DNS Backend API is running on port ${port}`);
    });
  }

  async addDNSRecord(req, res) {
    const { domain } = req.params;
    const { recordType, value } = req.body;

    if (!domain || !recordType || value === undefined) {
      return res
        .status(400)
        .json({ error: "Missing required fields: domain, recordType, value" });
    }

    try {
      const formattedValue = this.formatAndValidateRecordValue(
        recordType,
        value
      );
      await this.redis.hset(
        domain,
        recordType.toUpperCase(),
        JSON.stringify(formattedValue)
      );
      await this.redis.sadd("domains", domain);
      logger.info(`Added record`, {
        domain,
        recordType: recordType.toUpperCase(),
        value: formattedValue,
      });
      res.status(201).json({ message: "DNS record added successfully" });
    } catch (error) {
      logger.error("Error adding DNS record", { error: error.message });
      res.status(400).json({ error: error.message });
    }
  }

  async getDNSRecords(req, res) {
    const { domain } = req.params;

    if (!domain) {
      return res.status(400).json({ error: "Missing required field: domain" });
    }

    try {
      const records = await this.redis.hgetall(domain);
      if (Object.keys(records).length === 0) {
        return res.status(404).json({ error: "Domain not found" });
      }

      // Parse JSON strings
      const parsedRecords = {};
      for (const [type, data] of Object.entries(records)) {
        parsedRecords[type] = JSON.parse(data);
      }

      res.status(200).json({ domain, records: parsedRecords });
    } catch (error) {
      logger.error("Error fetching DNS records", { error: error.message });
      res.status(500).json({ error: "Internal server error" });
    }
  }

  async deleteDNSRecord(req, res) {
    const { domain, recordType } = req.params;

    if (!domain || !recordType) {
      return res
        .status(400)
        .json({ error: "Missing required fields: domain, recordType" });
    }

    try {
      const result = await this.redis.hdel(domain, recordType.toUpperCase());
      if (result === 0) {
        return res
          .status(404)
          .json({ error: "Record type not found for the domain" });
      }

      // Check if domain has any remaining records
      const remaining = await this.redis.hlen(domain);
      if (remaining === 0) {
        await this.redis.srem("domains", domain);
      }

      logger.info(`Deleted record`, {
        domain,
        recordType: recordType.toUpperCase(),
      });
      res.status(200).json({ message: "DNS record deleted successfully" });
    } catch (error) {
      logger.error("Error deleting DNS record", { error: error.message });
      res.status(500).json({ error: "Internal server error" });
    }
  }

  async listDomains(req, res) {
    try {
      const domains = await this.redis.smembers("domains");
      res.status(200).json({ domains });
    } catch (error) {
      logger.error("Error listing domains", { error: error.message });
      res.status(500).json({ error: "Internal server error" });
    }
  }

  formatAndValidateRecordValue(recordType, value) {
    switch (recordType.toUpperCase()) {
      case "A":
        if (!this.isValidIPv4(value)) {
          throw new Error("Invalid IPv4 address");
        }
        return value;
      case "AAAA":
        if (!this.isValidIPv6(value)) {
          throw new Error("Invalid IPv6 address");
        }
        return value; // No expansion needed
      case "NS":
      case "CNAME":
      case "PTR":
        if (!this.isValidDomainName(value)) {
          throw new Error("Invalid domain name");
        }
        return value;
      case "MX":
        if (!this.isValidMX(value)) {
          throw new Error("Invalid MX record");
        }
        return value;
      case "TXT":
        if (!this.isValidTXT(value)) {
          throw new Error("Invalid TXT record");
        }
        return value;
      case "SOA":
        if (!this.isValidSOA(value)) {
          throw new Error("Invalid SOA record");
        }
        return value;
      case "SRV":
        if (!this.isValidSRV(value)) {
          throw new Error("Invalid SRV record");
        }
        return value;
      case "CAA":
        if (!this.isValidCAA(value)) {
          throw new Error("Invalid CAA record");
        }
        return value;
      default:
        throw new Error("Unsupported record type");
    }
  }

  isValidIPv4(ip) {
    return net.isIPv4(ip);
  }

  isValidIPv6(ip) {
    return net.isIPv6(ip);
  }

  isValidDomainName(domain) {
    try {
      const punyEncoded = punycode.toASCII(domain);
      return (
        /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(punyEncoded) &&
        punyEncoded.length <= 253
      );
    } catch (e) {
      return false;
    }
  }

  isValidMX(value) {
    if (
      typeof value !== "object" ||
      value.preference === undefined ||
      value.exchange === undefined
    ) {
      return false;
    }
    return (
      Number.isInteger(value.preference) &&
      this.isValidDomainName(value.exchange)
    );
  }

  isValidTXT(value) {
    return typeof value === "string" && value.length <= 255;
  }

  isValidSOA(value) {
    if (typeof value !== "object") return false;
    const { mname, rname, serial, refresh, retry, expire, minimum } = value;
    return (
      this.isValidDomainName(mname) &&
      this.isValidDomainName(rname) &&
      Number.isInteger(serial) &&
      Number.isInteger(refresh) &&
      Number.isInteger(retry) &&
      Number.isInteger(expire) &&
      Number.isInteger(minimum)
    );
  }

  isValidSRV(value) {
    if (typeof value !== "object") return false;
    const { priority, weight, port, target } = value;
    return (
      Number.isInteger(priority) &&
      Number.isInteger(weight) &&
      Number.isInteger(port) &&
      this.isValidDomainName(target)
    );
  }

  isValidCAA(value) {
    if (typeof value !== "object") return false;
    const { flags, tag, value: caaValue } = value;
    return (
      Number.isInteger(flags) &&
      flags >= 0 &&
      flags <= 255 &&
      ["issue", "issuewild", "iodef"].includes(tag) &&
      typeof caaValue === "string"
    );
  }
}

module.exports = { DNSServer, DNSBackend };
