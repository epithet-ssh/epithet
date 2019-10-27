FROM ubuntu:16.04

RUN apt-get update && apt-get install -y openssh-server
# RUN apt-get install -y openssh-server
RUN mkdir /var/run/sshd
RUN echo 'root:waffle' | chpasswd
RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

ENV NOTVISIBLE "in users profile"
RUN echo "export VISIBLE=now" >> /etc/profile

EXPOSE 22

RUN mkdir /etc/ssh/auth_principals
RUN chmod 0755 /etc/ssh/auth_principals

COPY ca.pub /etc/ssh/ca.pub
COPY sshd_config /etc/ssh/sshd_config
COPY auth_principals/* /etc/ssh/auth_principals/
RUN chmod 0644 /etc/ssh/sshd_config /etc/ssh/ca.pub

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
