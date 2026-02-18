FROM ubuntu:22.04


ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip sudo openssh-server openssh-client sshpass iproute2 iputils-ping \
    wget gpg ca-certificates \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# --- Vault installation (HashiCorp official repo) ---
RUN wget -O- https://apt.releases.hashicorp.com/gpg \
    | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg \
  && echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com jammy main" \
    > /etc/apt/sources.list.d/hashicorp.list \
  && apt-get update \
  && apt-get install -y --no-install-recommends vault \
  && setcap -r /usr/bin/vault || true \
  && rm -rf /var/lib/apt/lists/* \
  && setcap -r /usr/bin/vault || true

RUN mkdir -p /var/run/sshd

RUN useradd -m -s /bin/bash quditto \
  && echo 'quditto:quditto' | chpasswd \
  && usermod -aG sudo quditto \
  && echo 'quditto ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# SSH config
RUN echo 'PermitRootLogin no' >> /etc/ssh/sshd_config \
  && echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config \
  && echo 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config

EXPOSE 22

USER quditto
WORKDIR /home/quditto
ENV PATH="/home/quditto/.local/bin:${PATH}"

RUN pip install --no-cache-dir --upgrade pip && \
  pip install --no-cache-dir PyYAML pydantic && \
  pip install --no-cache-dir --index-url https://test.pypi.org/simple/ \
      --extra-index-url https://pypi.org/simple \
      --pre qd2-node-dev

CMD ["sudo", "/usr/sbin/sshd", "-D", "-e"]
