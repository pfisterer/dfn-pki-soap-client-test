FROM openjdk:14-alpine

# Add User/Group
RUN addgroup -S pki
RUN adduser -S pki -G pki

# Add libs and entrypoint
ADD lib/ /app/lib/
ADD entrypoint.sh /app/
RUN chmod a+x /app/entrypoint.sh

# Create classpath
WORKDIR /app
RUN echo "/app/src/:`echo /app/lib/*.jar | tr ' ' ':') *.java`" > /app/cp.txt
RUN echo Classpath is `cat /app/cp.txt`

# Add source
WORKDIR /app/src
ADD src/ /app/src/

RUN chown -R pki:pki /app
USER pki

# Compile
RUN javac -cp `cat /app/cp.txt` *.java

VOLUME /data
ENTRYPOINT ["/app/entrypoint.sh"]
CMD [""]


