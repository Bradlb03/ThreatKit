FROM jupyter/scipy-notebook:python-3.11
WORKDIR /home/jovyan/work

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
        yara \
        libyara-dev \
        yara-doc \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --upgrade "scikit-learn>=1.7,<1.8"

USER ${NB_UID}