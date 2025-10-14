FROM jupyter/scipy-notebook:python-3.11
WORKDIR /home/jovyan/work

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
        yara libyara-dev yara-doc \
    && rm -rf /var/lib/apt/lists/*
USER ${NB_UID}