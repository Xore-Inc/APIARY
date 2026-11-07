FROM dinotools/dionaea:latest@sha256:6f06d0a6035c865cb60ef51bd96ff3b1f25ee4bfcd852dad3f551bc2d93464ca

# getfacl/setfacl, for store_acl_patch.py. A captured payload is hardlinked
# into download.dir, and a hardlink carries the inode's permissions rather than
# the directory's default ACL -- so the one entry that lets the inventory
# worker read the sample has to be applied explicitly (#1789).
RUN apt-get update \
    && apt-get install -y --no-install-recommends acl \
    && rm -rf /var/lib/apt/lists/*

# No USER directive: the base image already runs as root by default
# (confirmed via `docker inspect --format '{{.Config.User}}'`, empty) so
# dionaea can bind its privileged ports (21, 69, 445, ...); this Dockerfile
# must not change that.
COPY tftp_patch.py /tmp/tftp_patch.py
COPY printer_patch.py /tmp/printer_patch.py
COPY ftp_patch.py /tmp/ftp_patch.py
COPY smb_exploit_patch.py /tmp/smb_exploit_patch.py
COPY sip_patch.py /tmp/sip_patch.py
COPY log_rotation_patch.py /tmp/log_rotation_patch.py
COPY store_acl_patch.py /tmp/store_acl_patch.py
COPY mssql_patch.py /tmp/mssql_patch.py
RUN python3 /tmp/tftp_patch.py \
    && python3 /tmp/printer_patch.py \
    && python3 /tmp/ftp_patch.py \
    && python3 /tmp/smb_exploit_patch.py \
    && python3 /tmp/sip_patch.py \
    && python3 /tmp/log_rotation_patch.py \
    && python3 /tmp/store_acl_patch.py \
    && python3 /tmp/mssql_patch.py \
    && rm /tmp/tftp_patch.py /tmp/printer_patch.py /tmp/ftp_patch.py /tmp/smb_exploit_patch.py /tmp/sip_patch.py /tmp/log_rotation_patch.py /tmp/store_acl_patch.py /tmp/mssql_patch.py
