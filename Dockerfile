FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH avclass.AVclass

# Switch to assemblyline user
USER assemblyline

# Copy service code
WORKDIR /opt/al_service
COPY . .
