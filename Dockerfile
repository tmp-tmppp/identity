# Identity provider of Chance: Keycloak 26 as an optimized image (the build options are fixed at build time, so the
# server starts faster and uses less memory) with the realm "chance" for the first start. The base image is pinned
# by tag and digest; Dependabot proposes updates.

# --- build stage: fix the build-time options ----------------------------------------------------------------
FROM quay.io/keycloak/keycloak:26.8.2@sha256:3879c623248408de29a5303178b5816c77e8dfef3890c361f8c0bbeaa979ba3b AS build
ENV KC_DB=postgres \
    KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=true \
    KC_HTTP_METRICS_HISTOGRAMS_ENABLED=true \
    KC_CACHE=local \
    KC_FEATURES=update-email
RUN /opt/keycloak/bin/kc.sh build

# --- runtime stage ------------------------------------------------------------------------------------------
FROM quay.io/keycloak/keycloak:26.8.2@sha256:3879c623248408de29a5303178b5816c77e8dfef3890c361f8c0bbeaa979ba3b
COPY --from=build /opt/keycloak/ /opt/keycloak/
COPY --chown=1000:0 realm/chance-realm.json /opt/keycloak/data/import/chance-realm.json
COPY --chown=1000:0 --chmod=0555 docker-entrypoint.sh /opt/keycloak/bin/docker-entrypoint.sh

# TLS ends at the gateway, which forwards the original host and scheme in X-Forwarded-* headers.
ENV KC_HTTP_ENABLED=true \
    KC_PROXY_HEADERS=xforwarded \
    KC_METRICS_ENABLED=true \
    KC_HTTP_METRICS_HISTOGRAMS_ENABLED=true \
    KC_CACHE=local

USER 1000
# 8080: the realm and its OpenID Connect endpoints; 9000: health and Prometheus metrics (management interface, never
# public: not in the Service, not routed by the gateway; REQ-20).
EXPOSE 8080 9000
ENTRYPOINT ["/opt/keycloak/bin/docker-entrypoint.sh"]
CMD ["start", "--optimized", "--import-realm"]
