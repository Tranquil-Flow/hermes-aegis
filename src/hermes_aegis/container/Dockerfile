FROM python:3.11-slim

RUN groupadd -r hermes && useradd -r -g hermes -d /home/hermes -s /bin/bash hermes
RUN mkdir -p /home/hermes /workspace /tmp/hermes && \
    chown -R hermes:hermes /home/hermes /workspace /tmp/hermes

RUN pip install --no-cache-dir hermes-agent

USER hermes
WORKDIR /workspace

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["hermes"]
