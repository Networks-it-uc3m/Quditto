FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip sudo openssh-server openssh-client sshpass nano iproute2 iputils-ping

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

RUN pip install --no-cache-dir --upgrade pip \
  && pip install --no-cache-dir qd2_orchestrator

CMD ["sudo", "/usr/sbin/sshd", "-D", "-e"]