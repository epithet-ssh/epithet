TMP := "/srv/epithet-server"

.PHONY: server
server: prep
	sudo /usr/sbin/sshd -f $(TMP)/sshd_config -d
 
prep:
	sudo rm -rf $(TMP)
	sudo mkdir -p $(TMP)
	sudo chmod 0700 $(TMP)
	sudo cp -r * $(TMP)/
	sudo find $(TMP) -type d -exec chmod 0700 {} \;
	sudo find $(TMP) -type f -exec chmod 0700 {} \;
