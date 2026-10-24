FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN apk add --no-cache python3 yara
WORKDIR /app
COPY scanner.py /app/scanner.py
COPY rules /rules
RUN mkdir -p /results
ENTRYPOINT ["python3", "/app/scanner.py"]
