FROM cccs/assemblyline-v4-service-base:latest

RUN pip install bpython

ENV SERVICE_PATH avclass_.AVclass

# Switch to assemblyline user
USER assemblyline

# Copy service code
WORKDIR /opt/al_service
COPY . .
