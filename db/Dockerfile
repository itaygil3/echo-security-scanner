FROM postgres:16

# Scripts in this directory run (in name order) on first start of an empty data volume.
COPY init/ /docker-entrypoint-initdb.d/
