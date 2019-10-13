FROM eg_sshd:1

RUN mkdir /etc/ssh/auth_principals
RUN chmod 0755 /etc/ssh/auth_principals

COPY ca.pub /etc/ssh/ca.pub
COPY sshd_config /etc/ssh/sshd_config
COPY auth_principals/* /etc/ssh/auth_principals/
RUN chmod 0644 /etc/ssh/sshd_config /etc/ssh/ca.pub

EXPOSE 22
CMD ["/usr/sbin/sshd", "-d"]
