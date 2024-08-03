# Switch to console mode

sudo update-grub
sudo systemctl enable multi-user.target --force
sudo systemctl set-default multi-user.target

# Undoing text mode 

sudo systemctl enable graphical.target --force
sudo systemctl set-default graphical.target