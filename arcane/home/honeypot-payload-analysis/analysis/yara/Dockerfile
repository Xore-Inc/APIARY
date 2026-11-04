FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache python3 yara
WORKDIR /app
COPY scanner.py /app/scanner.py
COPY rules /rules
RUN mkdir -p /results
ENTRYPOINT ["python3", "/app/scanner.py"]
