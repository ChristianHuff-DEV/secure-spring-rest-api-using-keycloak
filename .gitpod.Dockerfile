FROM gitpod/workspace-full-vnc

# Install Java 17 and make it the default
RUN bash -c ". /home/gitpod/.sdkman/bin/sdkman-init.sh && \
    sdk install java 21.0.1-tem && \
    sdk default java 21.0.1-tem"
