FROM bitnami/keycloak:18.0.0-debian-11-r7

# Set environment variables
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US.UTF-8

# Create directory for H2 database
RUN mkdir -p /opt/bitnami/keycloak/data/h2

# Copy realm data for import at startup (Bitnami specific path)
COPY ./.infrastructure/keycloak/cba-dev-realm.json /opt/bitnami/keycloak/data/import/

# Expose service port (Keycloak default)
EXPOSE 8080

# Start Keycloak (Bitnami specific entrypoint with realm import)
ENTRYPOINT ["/opt/bitnami/keycloak/bin/kc.sh", "start-dev", "--import-realm"]
