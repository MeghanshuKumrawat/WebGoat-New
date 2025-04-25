FROM docker.io/eclipse-temurin:23-jdk-noble

LABEL name="WebGoat Test Environment"
LABEL maintainer="WebGoat team"

# Create non-root user for security
RUN \
  useradd -ms /bin/bash webgoat && \
  chgrp -R 0 /home/webgoat && \
  chmod -R g=u /home/webgoat

# Set user to non-root
USER webgoat

WORKDIR /home/webgoat

COPY --chown=webgoat ./target/*.jar /home/webgoat/app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/home/webgoat/app.jar"]