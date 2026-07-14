FROM cgr.dev/chainguard/wolfi-base@sha256:02dab76bd852a70556b5b2002195c8a5fdab77d323c433bf6642aab080489795 AS build
RUN apk add --no-cache openjdk-8 maven-3.9 && rm -rf /var/cache/apk/*
ENV JAVA_HOME=/usr/lib/jvm/java-1.8-openjdk
ENV PATH="$JAVA_HOME/bin:/usr/share/java/maven/bin:$PATH"

USER nonroot
WORKDIR /home/nonroot
COPY --chown=nonroot:nonroot pom.xml .
COPY --chown=nonroot:nonroot src/ src/
RUN mvn package -B

FROM build AS test
USER nonroot
CMD ["mvn", "-B", "test"]
