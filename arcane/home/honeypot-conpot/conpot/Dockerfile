# #2619: pinned to dtagdevsec/conpot:24.04.1 at a fixed manifest-list
# digest. #2314 held this at 24.04 on the belief that 24.04.1 had moved
# conpot's files around; it had not. The only difference that mattered is
# the Python install root -- conpot ships under 3.12 in 24.04.1, so
# /usr/lib/python3.11/site-packages/conpot became
# /usr/lib/python3.12/site-packages/conpot with the package layout below
# it unchanged. All six *_patch.py scripts were retargeted accordingly.
# Keep the @sha256: pin: a bare tag is mutable and could roll onto an
# image with a different Python root, breaking every patch at build time.
FROM dtagdevsec/conpot:24.04.2@sha256:be17a238709c78909c7d2e0da55bc3ea66dc3aa46618f0d89b7080f3e7dda3e8

USER root
COPY persona_patch.py /tmp/persona_patch.py
COPY proxy_patch.py /tmp/proxy_patch.py
COPY s7comm_patch.py /tmp/s7comm_patch.py
COPY modbus_patch.py /tmp/modbus_patch.py
COPY guardian_ast_patch.py /tmp/guardian_ast_patch.py
COPY iec104_patch.py /tmp/iec104_patch.py
COPY json_log_rotation_patch.py /tmp/json_log_rotation_patch.py
COPY healthcheck.py /usr/local/bin/conpot-healthcheck.py
RUN python3 /tmp/persona_patch.py && python3 /tmp/proxy_patch.py && python3 /tmp/s7comm_patch.py && python3 /tmp/modbus_patch.py && python3 /tmp/guardian_ast_patch.py && python3 /tmp/iec104_patch.py && python3 /tmp/json_log_rotation_patch.py \
    && rm /tmp/persona_patch.py /tmp/proxy_patch.py /tmp/s7comm_patch.py /tmp/modbus_patch.py /tmp/guardian_ast_patch.py /tmp/iec104_patch.py /tmp/json_log_rotation_patch.py \
    && chmod 755 /usr/local/bin/conpot-healthcheck.py
USER conpot
