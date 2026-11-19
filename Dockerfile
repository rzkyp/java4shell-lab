# Java4Shell lab image - run on an AVX-512 VBMI host (Intel Ice Lake+/Tiger Lake, AMD Zen4+)
# NOTE: verify the base tag exists; ANY Temurin 17.0.6 - 17.0.21 build is vulnerable.
ARG BASE=eclipse-temurin:17.0.20.1_1-jre
FROM ${BASE}

WORKDIR /app
COPY VulnApp.java /app/VulnApp.java

EXPOSE 8080
CMD ["java", "-Dlab.port=8080", "-Dlab.log=/app/vulnapp.log", "/app/VulnApp.java"]
