
# syntax=docker/dockerfile:1.6

FROM ubuntu:22.04


ENV DEBIAN_FRONTEND=noninteractive LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8

# Base deps + RabbitMQ (no systemd), SSH server/client for Ansible, locale to avoid latin1 warning
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip sudo openssh-server openssh-client sshpass \
    rabbitmq-server erlang-base ca-certificates locales nano iproute2 iputils-ping\
 && sed -i 's/# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen \
 && locale-gen en_US.UTF-8 \
 && rm -rf /var/lib/apt/lists/*

# sshd needs this
RUN mkdir -p /var/run/sshd

# User with passwordless sudo (Ansible connects as this user)
RUN useradd -m -s /bin/bash quditto \
 && echo 'quditto:quditto' | chpasswd \
 && usermod -aG sudo quditto \
 && echo 'quditto ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# SSH config
RUN echo 'PermitRootLogin no' >> /etc/ssh/sshd_config \
 && echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config \
 && echo 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config

# Healthcheck: rabbit must answer ping
HEALTHCHECK --interval=5s --timeout=3s --retries=20 CMD rabbitmq-diagnostics -q ping || exit 1

EXPOSE 22 5672

# Entrypoint starts RabbitMQ (detached), waits until it's ready, then runs sshd in foreground
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# We’ll run commands via sudo inside entrypoint
USER quditto
WORKDIR /home/quditto
ENV PATH="/home/quditto/.local/bin:${PATH}"

RUN pip install --no-cache-dir --upgrade pip && \
  pip install --no-cache-dir PyYAML pydantic 


RUN --mount=type=secret,id=netsquid_pipconf,target=/run/secrets/pip.conf,uid=1000,gid=1000,mode=0400 \
  PIP_CONFIG_FILE=/run/secrets/pip.conf \
  pip install --no-cache-dir --user netsquid && \
  pip install --no-cache-dir --user qd2_controller



ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/sbin/sshd", "-D", "-e"]
