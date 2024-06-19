FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc gdb git make cmake \
    python3 python3-pip python3-setuptools python3-dev ipython3 && \
    apt-get clean autoclean && \
    apt-get autoremove

RUN pip3 install --upgrade pip && \
    pip3 install --no-cache-dir \
    angr pyyaml

# RUN addgroup --gid 1000 vscode
# RUN adduser --disabled-password --gecos "" --uid 1000 --gid 1000 vscode
# USER vscode
# ENV HOME /home/vscode