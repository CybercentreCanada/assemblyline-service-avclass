ARG branch=latest
ARG base=cccs/assemblyline-v4-service-base
FROM $base:$branch

ENV SERVICE_PATH avclass_service.AVClass

USER root

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Switch to assemblyline user
USER assemblyline

# Install python dependencies
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir --user --requirement requirements.txt && rm -rf ~/.cache/pip

# Copy service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.3.stable
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
