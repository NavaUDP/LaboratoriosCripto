# C4/S1: Ubuntu 22.10
FROM ubuntu:22.10

#Cambiar los repositorios a los archivados
RUN sed -i 's/archive.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list && \
    sed -i 's/security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list

# Actualizar paquetes y configurar OpenSSH (Cliente y Servidor)
RUN apt-get update && \
    apt-get install -y openssh-client openssh-server && \
    apt-get clean

# Configurar usuario "prueba" con contraseña "prueba"
RUN useradd -m -s /bin/bash prueba && \
    echo "prueba:prueba" | chpasswd

# Configurar el servidor SSH
RUN mkdir -p /var/run/sshd
EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
